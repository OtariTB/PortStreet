"""Integration tests for Direct3D 9 Genuine Executable Recompilation (Substep 4.1.4).

Verifies that genuine lifted ProStreet x86 functions (sub_0070e150 and sub_00705d30)
execute through WebAssembly, invoke Direct3DCreate9, enumerate capabilities,
call CreateDevice, emit the initial frame command stream (BeginScene, Clear,
EndScene, Present) to the shared memory ring buffer, and increment frame_index.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

WORKSPACE = Path(__file__).resolve().parent.parent


class TestD3D9WasmIntegration(unittest.TestCase):
    """End-to-end integration tests using genuine recompiled WebAssembly code."""

    def test_genuine_d3d9_boot_and_scene_rendering_wasm(self):
        """Executes genuine sub_0070e150 and sub_00705d30 via WebAssembly in Node.js."""
        # 1. Verify / run tools/lift_d3d9.py to ensure up-to-date WASM compilation
        lift_script = WORKSPACE / "tools" / "lift_d3d9.py"
        self.assertTrue(lift_script.is_file(), f"tools/lift_d3d9.py must exist at {lift_script}")

        res_lift = subprocess.run(
            ["python", str(lift_script)],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(WORKSPACE),
        )
        self.assertEqual(
            res_lift.returncode,
            0,
            f"tools/lift_d3d9.py failed ({res_lift.returncode}):\n{res_lift.stdout}\n{res_lift.stderr}",
        )

        # 2. Run Node.js integration harness
        test_script = WORKSPACE / "tests" / "test_d3d9_wasm.mjs"
        self.assertTrue(test_script.is_file(), f"test_d3d9_wasm.mjs must exist at {test_script}")

        res_node = subprocess.run(
            ["node", str(test_script)],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(WORKSPACE),
        )
        self.assertEqual(
            res_node.returncode,
            0,
            f"tests/test_d3d9_wasm.mjs failed ({res_node.returncode}):\n{res_node.stdout}\n{res_node.stderr}",
        )

        # 3. Parse JSON output report
        stdout = res_node.stdout
        json_start = stdout.find("{")
        self.assertGreaterEqual(json_start, 0, "test_d3d9_wasm.mjs must output JSON report")
        report = json.loads(stdout[json_start:])

        # 4. Validate report assertions
        self.assertEqual(report.get("status"), "PASS")
        self.assertEqual(len(report.get("functionsExecuted", [])), 2)

        fn0 = report["functionsExecuted"][0]
        self.assertEqual(fn0["name"], "sub_0070e150")
        self.assertEqual(fn0["address"], "0x0070e150")
        self.assertEqual(fn0["storedDirect3D9"], "0x27801080")
        self.assertIn("Direct3DCreate9(SDKVersion=32)", fn0["callsMade"])
        self.assertTrue(any("GetDeviceCaps" in c for c in fn0["callsMade"]))
        self.assertTrue(any("GetAdapterIdentifier" in c for c in fn0["callsMade"]))

        fn1 = report["functionsExecuted"][1]
        self.assertEqual(fn1["name"], "sub_00705d30")
        self.assertEqual(fn1["address"], "0x00705d30")
        self.assertEqual(fn1["storedDevice"], "0x27801300")
        self.assertEqual(fn1["returnValue"], "0x00000000 (D3D_OK)")
        self.assertTrue(any("CreateDevice" in c for c in fn1["callsMade"]))
        self.assertTrue(any("BeginScene" in c for c in fn1["callsMade"]))
        self.assertTrue(any("Clear" in c for c in fn1["callsMade"]))
        self.assertTrue(any("EndScene" in c for c in fn1["callsMade"]))
        self.assertTrue(any("Present" in c for c in fn1["callsMade"]))

        ring = report.get("ringBuffer", {})
        self.assertEqual(ring.get("magic"), "0x39443344")
        self.assertEqual(ring.get("version"), 1)
        self.assertEqual(ring.get("frameIndex"), 1)

        cmds = [c["type"] for c in ring.get("commandsEmitted", [])]
        self.assertEqual(cmds, ["BEGIN_SCENE", "CLEAR", "END_SCENE", "PRESENT"])


if __name__ == "__main__":
    unittest.main()
