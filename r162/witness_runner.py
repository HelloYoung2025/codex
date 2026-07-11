#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile


REJECT_CODE = 42


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json_bytes(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)


def strict_json_file(path):
    return strict_json_bytes(pathlib.Path(path).read_bytes())


def verify_manifest(bundle):
    manifest = strict_json_file(bundle / "manifest.json")
    expected = manifest.get("files")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("manifest files missing")
    for name, expected_hash in sorted(expected.items()):
        target = bundle / name
        if not target.is_file() or target.is_symlink():
            raise ValueError(f"manifest target invalid: {name}")
        actual = sha256_file(target)
        if actual != expected_hash:
            raise ValueError(f"manifest mismatch: {name}")
    return manifest


def run(command, *, check=False, input_text=None):
    completed = subprocess.run(
        command,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed {command}: {completed.stderr}")
    return completed


def sudo_as(user, script):
    return run(["sudo", "-u", user, "--", "sh", "-c", script])


def read_text_as(user, path):
    completed = run(["sudo", "-u", user, "--", "cat", str(path)])
    if completed.returncode != 0:
        raise RuntimeError(f"failed to read {path} as {user}: {completed.stderr.strip()}")
    return completed.stdout


def strict_json_as(user, path):
    return strict_json_bytes(read_text_as(user, path).encode("utf-8"))


def sha256_as(user, path):
    completed = run(["sudo", "-u", user, "--", "sha256sum", str(path)])
    if completed.returncode != 0:
        raise RuntimeError(f"failed to hash {path} as {user}: {completed.stderr.strip()}")
    return completed.stdout.split()[0]


def exists_as(user, path):
    return run(["sudo", "-u", user, "--", "test", "-e", str(path)]).returncode == 0


def record(checks, name, passed, detail=None):
    checks.append({"name": name, "passed": bool(passed), "detail": detail or ""})


def reject(message):
    print(message, file=sys.stderr)
    return REJECT_CODE


def validate_proposal(args):
    bundle = pathlib.Path(args.bundle).resolve()
    verify_manifest(bundle)
    subject = strict_json_file(bundle / "subject.json")
    policy = strict_json_file(bundle / "policy.json")
    proposal_dir = pathlib.Path(args.proposal_dir).resolve()
    proposal_path = pathlib.Path(args.proposal)
    state_path = pathlib.Path(args.state)

    try:
        if proposal_path.parent.resolve() != proposal_dir:
            return reject("proposal path escaped proposal directory")
        metadata = os.lstat(proposal_path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return reject("proposal must be a regular non-symlink file")
        if metadata.st_size > policy["max_proposal_bytes"]:
            return reject("proposal exceeds size cap")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(proposal_path, flags)
        try:
            raw = os.read(descriptor, policy["max_proposal_bytes"] + 1)
        finally:
            os.close(descriptor)
        proposal = strict_json_bytes(raw)
        expected_keys = {
            "proposal_id",
            "expected_state_version",
            "challenge_nonce",
            "action",
            "value",
        }
        if set(proposal) != expected_keys:
            return reject("proposal fields are not exact")
        state = strict_json_file(state_path)
        if state.get("challenge_nonce") != subject["challenge_nonce"]:
            return reject("state subject nonce mismatch")
        if state.get("nonce_consumed"):
            return reject("challenge nonce already consumed")
        if proposal["expected_state_version"] != state.get("version"):
            return reject("stale state version")
        if proposal["challenge_nonce"] != subject["challenge_nonce"]:
            return reject("proposal nonce mismatch")
        if proposal["action"] != policy["allowed_action"]:
            return reject("action not allowed")
        if proposal["value"] != policy["allowed_value"]:
            return reject("value not allowed")

        new_state = {
            "version": state["version"] + 1,
            "challenge_nonce": state["challenge_nonce"],
            "nonce_consumed": True,
            "last_proposal_id": proposal["proposal_id"],
            "marker": proposal["value"],
        }
        temp_path = state_path.with_name(f".{state_path.name}.tmp-{os.getpid()}")
        with open(temp_path, "wb") as handle:
            handle.write(canonical_bytes(new_state) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, state_path)
        directory_fd = os.open(state_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return reject(str(exc))


def write_proposal(path, value, *, duplicate=False, user=None):
    if duplicate:
        raw = (
            '{"proposal_id":"duplicate","proposal_id":"forged",'
            '"expected_state_version":1,"challenge_nonce":"x",'
            '"action":"commit_marker","value":"hosted-witness-verified"}\n'
        )
    else:
        raw = (canonical_bytes(value) + b"\n").decode("utf-8")
    if user is None:
        path.write_text(raw, encoding="utf-8")
        os.chmod(path, 0o644)
        return
    writer = (
        "import os,pathlib,sys; "
        "p=pathlib.Path(sys.argv[1]); p.write_text(sys.stdin.read(),encoding='utf-8'); os.chmod(p,0o644)"
    )
    run(["sudo", "-u", user, "--", sys.executable, "-c", writer, str(path)], check=True, input_text=raw)


def execute(args):
    bundle = pathlib.Path(args.bundle).resolve()
    manifest = verify_manifest(bundle)
    subject = strict_json_file(bundle / "subject.json")
    plan = strict_json_file(bundle / "plan.json")
    checks = []

    env_checks = {
        "CI": os.environ.get("CI") == "true",
        "GITHUB_ACTIONS": os.environ.get("GITHUB_ACTIONS") == "true",
        "RUNNER_OS": os.environ.get("RUNNER_OS") == "Linux",
        "GITHUB_RUN_ID": bool(os.environ.get("GITHUB_RUN_ID")),
        "GITHUB_JOB": bool(os.environ.get("GITHUB_JOB")),
        "GITHUB_SHA": bool(os.environ.get("GITHUB_SHA")),
        "R162_EXPECTED_HEAD_SHA": bool(os.environ.get("R162_EXPECTED_HEAD_SHA")),
    }
    record(checks, "hosted_environment_claim_present", all(env_checks.values()), json.dumps(env_checks, sort_keys=True))
    if not all(env_checks.values()):
        raise RuntimeError("required GitHub Actions environment missing")

    checkout_sha = run(["git", "rev-parse", "HEAD"], check=True).stdout.strip()
    expected_head_sha = os.environ["R162_EXPECTED_HEAD_SHA"]
    record(
        checks,
        "exact_head_checkout",
        checkout_sha == expected_head_sha,
        f"checkout={checkout_sha} expected={expected_head_sha} event={os.environ.get('GITHUB_SHA')}",
    )

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix="r162-", dir="/tmp"))
    os.chmod(temp_root, 0o755)
    pack_user = subject["pack_user"]
    agent_user = subject["agent_user"]
    users_created = []
    try:
        for user in (pack_user, agent_user):
            if run(["id", user]).returncode == 0:
                raise RuntimeError(f"fresh runner unexpectedly already has {user}")
            run(["sudo", "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user], check=True)
            users_created.append(user)

        pack_uid = pwd.getpwnam(pack_user).pw_uid
        agent_uid = pwd.getpwnam(agent_user).pw_uid
        record(checks, "distinct_uid", pack_uid != agent_uid and pack_uid != os.getuid() and agent_uid != os.getuid(), f"pack={pack_uid} agent={agent_uid} runner={os.getuid()}")

        pack_dir = temp_root / "pack"
        proposal_dir = temp_root / "proposals"
        run(["sudo", "install", "-d", "-o", pack_user, "-g", pack_user, "-m", "0700", str(pack_dir)], check=True)
        run(["sudo", "install", "-d", "-o", agent_user, "-g", agent_user, "-m", "0755", str(proposal_dir)], check=True)
        state_path = pack_dir / "state.json"
        initial_state = canonical_bytes({
            "version": subject["initial_state_version"],
            "challenge_nonce": subject["challenge_nonce"],
            "nonce_consumed": False,
            "last_proposal_id": None,
            "marker": None,
        }).decode("utf-8")
        create_state = f"umask 077; printf '%s\\n' '{initial_state}' > '{state_path}'"
        state_init = sudo_as(pack_user, create_state)
        if state_init.returncode != 0:
            raise RuntimeError(f"pack state initialization failed: {state_init.stderr.strip()}")
        initial_hash = sha256_as(pack_user, state_path)

        probes = [
            ("agent_read_denied", f"cat '{state_path}' >/dev/null"),
            ("agent_create_denied", f"touch '{pack_dir}/agent-created'"),
            ("agent_truncate_denied", f": > '{state_path}'"),
            ("agent_replace_denied", f"printf forged > '{state_path}'"),
            ("agent_rename_denied", f"mv '{state_path}' '{pack_dir}/moved.json'"),
            ("agent_child_denied", f"sh -c 'PACK_BYPASS=1 cat \"{state_path}\" >/dev/null'"),
        ]
        if args.mode == "reverse":
            probes.reverse()
        for name, script in probes:
            outcome = sudo_as(agent_user, script)
            record(checks, name, outcome.returncode != 0 and sha256_as(pack_user, state_path) == initial_hash, f"rc={outcome.returncode}")

        base_proposal = {
            "proposal_id": "proposal-valid-001",
            "expected_state_version": subject["initial_state_version"],
            "challenge_nonce": subject["challenge_nonce"],
            "action": "commit_marker",
            "value": "hosted-witness-verified",
        }
        cases = []
        stale = dict(base_proposal, proposal_id="stale", expected_state_version=0)
        wrong_nonce = dict(base_proposal, proposal_id="wrong-nonce", challenge_nonce="forged")
        for filename, value, check_name in (
            ("stale.json", stale, "stale_version_rejected"),
            ("wrong-nonce.json", wrong_nonce, "wrong_nonce_rejected"),
        ):
            path = proposal_dir / filename
            write_proposal(path, value, user=agent_user)
            cases.append((check_name, path))
        duplicate_path = proposal_dir / "duplicate.json"
        write_proposal(duplicate_path, None, duplicate=True, user=agent_user)
        cases.append(("duplicate_key_rejected", duplicate_path))
        outside_path = temp_root / "outside.json"
        write_proposal(outside_path, base_proposal)
        cases.append(("path_escape_rejected", outside_path))
        symlink_path = proposal_dir / "linked.json"
        run(["sudo", "-u", agent_user, "--", "ln", "-s", str(outside_path), str(symlink_path)], check=True)
        cases.append(("symlink_rejected", symlink_path))

        validator = [
            "sudo", "-u", pack_user, "--", sys.executable, str(bundle / "witness_runner.py"),
            "validate", "--bundle", str(bundle), "--proposal-dir", str(proposal_dir), "--state", str(state_path),
        ]
        for check_name, proposal_path in cases:
            outcome = run(validator + ["--proposal", str(proposal_path)])
            record(checks, check_name, outcome.returncode == REJECT_CODE and sha256_as(pack_user, state_path) == initial_hash, f"rc={outcome.returncode}")

        valid_path = proposal_dir / "valid.json"
        write_proposal(valid_path, base_proposal, user=agent_user)
        outcome = run(validator + ["--proposal", str(valid_path)])
        committed_state = strict_json_as(pack_user, state_path)
        valid_commit = (
            outcome.returncode == 0
            and committed_state.get("version") == subject["expected_final_state_version"]
            and committed_state.get("nonce_consumed") is True
            and committed_state.get("last_proposal_id") == base_proposal["proposal_id"]
        )
        record(checks, "valid_proposal_committed_once", valid_commit, f"rc={outcome.returncode}")
        committed_hash = sha256_as(pack_user, state_path)
        replay = run(validator + ["--proposal", str(valid_path)])
        record(checks, "replay_rejected", replay.returncode == REJECT_CODE and sha256_as(pack_user, state_path) == committed_hash, f"rc={replay.returncode}")

        control_path = pack_dir / "pack-control.txt"
        control = sudo_as(pack_user, f"umask 077; printf pack-ok > '{control_path}'")
        record(checks, "pack_positive_control", control.returncode == 0 and read_text_as(pack_user, control_path) == "pack-ok")

        fd_gap_path = pack_dir / "preopened-fd-gap.txt"
        sudo_as(pack_user, f"umask 077; printf before > '{fd_gap_path}'")
        helper = (
            "import os,pwd; p='" + str(fd_gap_path) + "'; "
            "fd=os.open(p,os.O_WRONLY|os.O_APPEND); "
            "u=pwd.getpwnam('" + agent_user + "'); os.setgid(u.pw_gid); os.setuid(u.pw_uid); "
            "os.write(fd,b'-after-drop'); os.fsync(fd); os.close(fd)"
        )
        fd_gap = run(["sudo", sys.executable, "-c", helper])
        gap_observed = fd_gap.returncode == 0 and read_text_as(pack_user, fd_gap_path) == "before-after-drop"
        record(checks, "inherited_fd_gap_observed", gap_observed, "observed_not_contained" if gap_observed else fd_gap.stderr)

        final_state = strict_json_as(pack_user, state_path)
        postconditions = (
            final_state.get("version") == subject["expected_final_state_version"]
            and final_state.get("marker") == "hosted-witness-verified"
            and not exists_as(pack_user, pack_dir / "agent-created")
            and not exists_as(pack_user, pack_dir / "moved.json")
        )
        record(checks, "postconditions_hold", postconditions)

        if args.mode == "tamper":
            tampered = temp_root / "tampered-bundle"
            shutil.copytree(bundle, tampered)
            modified = strict_json_file(tampered / "subject.json")
            modified["challenge_nonce"] = "tampered-after-freeze"
            (tampered / "subject.json").write_bytes(canonical_bytes(modified) + b"\n")
            rejected = False
            try:
                verify_manifest(tampered)
            except ValueError:
                rejected = True
            record(checks, "tampered_manifest_rejected", rejected)

        failed = [item["name"] for item in checks if not item["passed"]]
        deterministic = {
            "subject_hash": manifest["files"]["subject.json"],
            "policy_hash": manifest["files"]["policy.json"],
            "plan_hash": manifest["files"]["plan.json"],
            "mode": args.mode,
            "checks": [{"name": item["name"], "passed": item["passed"]} for item in checks],
            "final_state": final_state,
            "inherited_fd_gap": "observed_not_contained" if gap_observed else "not_observed",
        }
        provider = {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "job": os.environ.get("GITHUB_JOB"),
            "event_sha": os.environ.get("GITHUB_SHA"),
            "checkout_sha": checkout_sha,
            "expected_head_sha": expected_head_sha,
            "ref": os.environ.get("GITHUB_REF"),
            "runner_name": os.environ.get("RUNNER_NAME"),
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
        }
        result = {
            "schema_version": "r162-hosted-result-v1",
            "candidate_id": "R162-r157-independent-hosted-ci-pack-agent-authority-witness",
            "subject_candidate_id": subject["subject_candidate_id"],
            "mode": args.mode,
            "blocking": bool(failed),
            "checks": checks,
            "checks_passed": len(checks) - len(failed),
            "checks_total": len(checks),
            "failed_checks": failed,
            "logical_root": hashlib.sha256(canonical_bytes(deterministic)).hexdigest(),
            "provider_execution_root": hashlib.sha256(canonical_bytes({"deterministic": deterministic, "provider": provider})).hexdigest(),
            "provider": provider,
            "uid_evidence": {"runner_uid": os.getuid(), "pack_uid": pack_uid, "agent_uid": agent_uid},
            "inherited_fd_gap": "observed_not_contained" if gap_observed else "not_observed",
            "human_acceptance_count": 0,
            "provider_sandbox_count": 0,
            "secret_usage_count": 0,
            "production_effect_count": 0,
            "claim_boundaries": [
                "GitHub-hosted execution is an independent execution domain, not an independent test author or expert reviewer",
                "Linux UID denial is not a complete sandbox, network-security boundary or malicious-code containment proof",
                "pre-acquired writable file descriptors remain usable after UID drop and are recorded as observed_not_contained",
                "CI success does not prove human acceptance, installation, deployment, production readiness or provider business-state safety",
            ],
        }
        pathlib.Path(args.output).write_bytes(json.dumps(result, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        print(json.dumps(result, sort_keys=True))
        return 1 if failed else 0
    finally:
        for user in reversed(users_created):
            run(["sudo", "userdel", user])
        run(["sudo", "rm", "-rf", "--", str(temp_root)])


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--bundle", required=True)
    execute_parser.add_argument("--mode", choices=("forward", "reverse", "tamper"), required=True)
    execute_parser.add_argument("--output", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--bundle", required=True)
    validate_parser.add_argument("--proposal-dir", required=True)
    validate_parser.add_argument("--proposal", required=True)
    validate_parser.add_argument("--state", required=True)
    args = parser.parse_args()
    if args.command == "validate":
        return validate_proposal(args)
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
