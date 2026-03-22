import os
import json
import time
from src.detector import MisuseDetector
from src.patcher import PatchGenerator

class ExperimentRunner:
    def __init__(self):
        self.detector = MisuseDetector()
        self.patcher = PatchGenerator()
        self.results = []

    def run_on_file(self, filepath):
        start = time.time()

        # Detection
        detection_result = self.detector.analyze_file(filepath)

        if detection_result.get("error"):
            return {
                "filepath": filepath,
                "status": "error",
                "error": detection_result["error"]
            }

        # Patch
        patch_result = self.patcher.process_file(detection_result)

        elapsed = time.time() - start

        # Build result record
        record = {
            "filepath": filepath,
            "misuses_detected": detection_result["total"],
            "unique_misuses": patch_result["misuses_found"] if "misuses_found" in patch_result else 0,
            "patch_status": patch_result["status"],
            "patch_success": patch_result["patches"][0]["success"] if patch_result["patches"] else False,
            "attempts": patch_result["patches"][0]["attempts"] if patch_result["patches"] else 0,
            "time_seconds": round(elapsed, 2),
            "misuse_types": list(set(m["rule_id"] for m in detection_result["misuses"])),
            "patched_code": patch_result["patches"][0]["patch"] if patch_result["patches"] and patch_result["patches"][0]["success"] else None
        }

        return record

    def run_on_directory(self, dirpath):
        all_files = []
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                if f.endswith(".py"):
                    all_files.append(os.path.join(root, f))

        print(f"Found {len(all_files)} Python files in {dirpath}")
        print("-" * 50)

        for i, filepath in enumerate(all_files):
            print(f"[{i+1}/{len(all_files)}] Processing: {os.path.basename(filepath)}")
            record = self.run_on_file(filepath)
            self.results.append(record)

            status_icon = "✓" if record.get("patch_success") else "✗"
            print(f"  {status_icon} Misuses: {record.get('misuses_detected',0)} | "
                  f"Status: {record.get('patch_status','error')} | "
                  f"Time: {record.get('time_seconds',0)}s")

        return self.results

    def save_results(self, output_path):
        with open(output_path, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults saved to {output_path}")

    def print_summary(self):
        if not self.results:
            print("No results yet")
            return

        total_files = len(self.results)
        files_with_misuses = sum(1 for r in self.results if r.get("misuses_detected", 0) > 0)
        total_misuses = sum(r.get("misuses_detected", 0) for r in self.results)
        successful_patches = sum(1 for r in self.results if r.get("patch_success", False))
        failed_patches = sum(1 for r in self.results if r.get("misuses_detected", 0) > 0 and not r.get("patch_success", False))
        errors = sum(1 for r in self.results if r.get("status") == "error")

        # Rule breakdown
        rule_counts = {}
        for r in self.results:
            for rule_id in r.get("misuse_types", []):
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

        avg_time = sum(r.get("time_seconds", 0) for r in self.results) / total_files if total_files > 0 else 0
        patch_rate = (successful_patches / files_with_misuses * 100) if files_with_misuses > 0 else 0

        print("\n" + "=" * 50)
        print("EXPERIMENT SUMMARY")
        print("=" * 50)
        print(f"Total files analyzed:      {total_files}")
        print(f"Files with misuses:        {files_with_misuses}")
        print(f"Total misuses detected:    {total_misuses}")
        print(f"Successfully patched:      {successful_patches}")
        print(f"Failed to patch:           {failed_patches}")
        print(f"Errors:                    {errors}")
        print(f"Patch success rate:        {patch_rate:.1f}%")
        print(f"Avg time per file:         {avg_time:.1f}s")
        print()
        print("Misuse breakdown by rule:")
        for rule_id, count in sorted(rule_counts.items()):
            print(f"  {rule_id}: {count} files")
        print("=" * 50)
