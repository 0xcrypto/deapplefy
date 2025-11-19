#!/usr/bin/env python3
"""
Deapplefy - Automated documentation generator for Apple Private Frameworks

Architecture (4 Layers):
1. Reverse Engineering (Static Analysis)
2. Usage Analysis
3. Runtime Analysis
4. AI Documentation
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FrameworkScanner:
    """Scans for private frameworks on macOS"""
    
    FRAMEWORK_PATHS = [
        "/System/Library/PrivateFrameworks",
        # "/System/Library/Frameworks",
    ]
    
    def __init__(self):
        self.frameworks: List[Path] = []
    
    def scan(self) -> List[Path]:
        """Scan for frameworks in standard locations"""
        logger.info("Scanning for frameworks...")
        
        for base_path in self.FRAMEWORK_PATHS:
            path = Path(base_path)
            if not path.exists():
                logger.warning(f"Path does not exist: {base_path}")
                continue
            
            # Find .framework directories
            try:
                for item in path.iterdir():
                    if item.is_dir() and item.suffix == ".framework":
                        self.frameworks.append(item)
                        logger.debug(f"Found framework: {item.name}")
            except PermissionError:
                logger.warning(f"Permission denied accessing: {base_path}")
        
        logger.info(f"Found {len(self.frameworks)} frameworks")
        return self.frameworks
    
    def is_macho(self, path: Path) -> bool:
        """Check if a file is a Mach-O binary"""
        try:
            if path.is_symlink() or not path.is_file():
                return False
                
            with open(path, 'rb') as f:
                magic = f.read(4)
                if len(magic) < 4:
                    return False
                # Mach-O magic numbers
                valid_magics = [
                    b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                    b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                    b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'
                ]
                return magic in valid_magics
        except Exception:
            return False

    def get_binary_path(self, framework_path: Path) -> Optional[Path]:
        """Get the main binary path from a framework"""
        framework_name = framework_path.stem
        
        # 1. Try standard locations first (fast path)
        candidates = [
            framework_path / framework_name,
            framework_path / "Versions" / "A" / framework_name,
            framework_path / "Versions" / "Current" / framework_name,
        ]
        
        for c in candidates:
            if c.exists() and self.is_macho(c):
                return c
        
        # 2. Search recursively for Mach-O files
        macho_files = []
        try:
            for p in framework_path.rglob("*"):
                if self.is_macho(p):
                    macho_files.append(p)
        except PermissionError:
            pass
            
        if not macho_files:
            return None
            
        # 3. Heuristics to pick the "main" binary
        for p in macho_files:
            if p.name == framework_name:
                return p
                
        return max(macho_files, key=lambda p: p.stat().st_size)


class StaticAnalyzer:
    """Layer 1: Static Analysis using radare2"""
    
    def __init__(self):
        self._check_tools()
        
    def _check_tools(self):
        try:
            subprocess.run(["r2", "-v"], capture_output=True, check=True)
            subprocess.run(["rabin2", "-v"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("radare2/rabin2 not installed.")
            sys.exit(1)

    def analyze(self, framework_path: Path, binary_path: Path) -> Dict[str, Any]:
        logger.info(f"  [Layer 1] Analyzing {framework_path.name}...")
        
        info = self._get_binary_info(binary_path)
        classes = self._extract_classes(binary_path)
        structure = self._scan_structure(framework_path)
        
        swift_metadata = self._extract_swift_metadata(binary_path)
        
        return {
            "layer": "static",
            "binary_info": info,
            "classes": classes,
            "swift_metadata": swift_metadata,
            "protocols": [],
            "structure": structure
        }

    def _extract_swift_metadata(self, binary_path: Path) -> Dict[str, Any]:
        """Extract Swift-specific metadata"""
        metadata = {
            "is_swift": False,
            "symbols": []
        }
        
        try:
            # Check for Swift symbols using nm or r2
            # We'll use r2 'isj' (symbols) and look for Swift mangling
            result = subprocess.run(
                ["r2", "-q", "-c", "isj", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    symbols = json.loads(result.stdout)
                    swift_symbols = []
                    for sym in symbols:
                        name = sym.get('name', '')
                        # Swift symbols often start with _$s or $s (demangled might differ)
                        # checking for 'Swift' in demangled name or specific prefixes
                        if '_$s' in name or '$s' in name or 'Swift' in sym.get('demname', ''):
                            swift_symbols.append(sym)
                            
                    if swift_symbols:
                        metadata["is_swift"] = True
                        metadata["symbols"] = swift_symbols[:100] # Limit for now
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.error(f"    Error extracting Swift metadata: {e}")
            
        return metadata

    def _scan_structure(self, framework_path: Path) -> Dict[str, Any]:
        """Scan framework directory structure including plists and CodeResources"""
        structure = {
            "files": [],
            "plists": {},
            "code_resources": None
        }
        
        try:
            for p in framework_path.rglob("*"):
                if p.is_file():
                    rel_path = str(p.relative_to(framework_path))
                    structure["files"].append(rel_path)
                    
                    if p.suffix.lower() == '.plist':
                        try:
                            # Use plutil to convert binary plists to json for easy reading
                            res = subprocess.run(
                                ["plutil", "-convert", "json", "-o", "-", str(p)],
                                capture_output=True,
                                text=True
                            )
                            if res.returncode == 0:
                                structure["plists"][rel_path] = json.loads(res.stdout)
                        except Exception as e:
                            logger.warning(f"    Failed to parse plist {rel_path}: {e}")
                            
                    if p.name == "CodeResources":
                        try:
                            # CodeResources is usually a plist
                            res = subprocess.run(
                                ["plutil", "-convert", "json", "-o", "-", str(p)],
                                capture_output=True,
                                text=True
                            )
                            if res.returncode == 0:
                                structure["code_resources"] = json.loads(res.stdout)
                        except Exception:
                            pass
                            
        except Exception as e:
            logger.error(f"    Error scanning structure: {e}")
            
        return structure

    def _get_binary_info(self, binary_path: Path) -> Dict[str, Any]:
        try:
            # rabin2 -I (info)
            res_info = subprocess.run(["rabin2", "-I", "-j", str(binary_path)], capture_output=True, text=True)
            info = json.loads(res_info.stdout) if res_info.stdout.strip() else {}
            
            # rabin2 -l (libs)
            res_libs = subprocess.run(["rabin2", "-l", "-j", str(binary_path)], capture_output=True, text=True)
            libs = json.loads(res_libs.stdout) if res_libs.stdout.strip() else []
            
            return {"info": info, "libraries": libs}
        except Exception as e:
            logger.error(f"    Error getting binary info: {e}")
            return {}

    def _extract_classes(self, binary_path: Path) -> List[Dict[str, Any]]:
        try:
            # r2 -c icj (classes in json)
            # We use a timeout because r2 can hang on complex binaries
            result = subprocess.run(
                ["r2", "-q", "-c", "icj", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    pass
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"    Timeout extracting classes for {binary_path.name}")
            return []
        except Exception as e:
            logger.error(f"    Error extracting classes: {e}")
            return []


class UsageAnalyzer:
    """Layer 2: Usage Analysis"""
    
    SCAN_PATHS = [
        "/System/Applications",
        "/System/Library/CoreServices",
        # "/Applications" # Too slow for now
    ]
    
    def analyze(self, framework_name: str, static_data: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"  [Layer 2] Analyzing usage for {framework_name}...")
        
        used_by = []
        known_classes = set()
        if static_data and "classes" in static_data:
            for cls in static_data["classes"]:
                if "name" in cls:
                    known_classes.add(cls["name"])
        
        # We'll scan a limited set of paths for now to avoid performance issues
        for base_path in self.SCAN_PATHS:
            path = Path(base_path)
            if not path.exists():
                continue
                
            try:
                # Find all bundles/executables
                for item in path.iterdir():
                    if item.suffix in ['.app', '.bundle']:
                        binary = self._get_bundle_binary(item)
                        if binary and self._links_against(binary, framework_name):
                            usage_info = {
                                "path": str(item),
                                "binary": str(binary),
                                "used_classes": self._find_used_classes(binary, known_classes)
                            }
                            used_by.append(usage_info)
            except Exception as e:
                logger.warning(f"    Error scanning {base_path}: {e}")
                
        return {
            "layer": "usage",
            "used_by": used_by
        }

    def _find_used_classes(self, binary_path: Path, known_classes: set) -> List[str]:
        """Find which framework classes are used by the binary"""
        used = []
        if not known_classes:
            return []
            
        try:
            # nm -u to find undefined symbols (imports)
            result = subprocess.run(
                ["nm", "-u", str(binary_path)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # ObjC class refs look like _OBJC_CLASS_$_ClassName
                    if "_OBJC_CLASS_$_" in line:
                        cls_name = line.split("_OBJC_CLASS_$_")[-1].strip()
                        if cls_name in known_classes:
                            used.append(cls_name)
        except Exception:
            pass
        return list(set(used))

    def _get_bundle_binary(self, bundle_path: Path) -> Optional[Path]:
        """Get the main binary of a bundle"""
        # Standard macOS bundle structure
        name = bundle_path.stem
        candidates = [
            bundle_path / "Contents" / "MacOS" / name,
            bundle_path / name
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def _links_against(self, binary_path: Path, framework_name: str) -> bool:
        """Check if a binary links against the framework"""
        try:
            # use otool -L or rabin2 -l
            # otool is usually faster/standard on mac
            result = subprocess.run(
                ["otool", "-L", str(binary_path)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                # Check if framework name appears in output
                # Frameworks are usually referenced as .../FrameworkName.framework/FrameworkName
                return f"/{framework_name}.framework/" in result.stdout
        except Exception:
            pass
        return False


class RuntimeAnalyzer:
    """Layer 3: Runtime Analysis"""
    
    def analyze(self, framework_path: Path) -> Dict[str, Any]:
        logger.info(f"  [Layer 3] Analyzing runtime for {framework_path.stem}...")
        
        # Try class-dump first (most robust for "runtime-like" headers)
        if self._has_class_dump():
            return self._analyze_with_class_dump(framework_path)
            
        # Fallback to ctypes/objc runtime (experimental)
        return self._analyze_with_ctypes(framework_path)

    def _has_class_dump(self) -> bool:
        try:
            subprocess.run(["class-dump", "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    def _analyze_with_class_dump(self, framework_path: Path) -> Dict[str, Any]:
        data = {"method": "class-dump", "headers": []}
        try:
            # class-dump -H -o <tmp> <framework>
            # We'll just dump to stdout for now to parse, or skip -H and just list
            # class-dump <framework> gives a full dump
            result = subprocess.run(
                ["class-dump", str(framework_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                # Very basic parsing or just storing the raw dump (it's huge)
                # Let's just store the size or first few lines for now to prove it works
                data["dump_size"] = len(result.stdout)
                data["preview"] = result.stdout[:500]
        except Exception as e:
            logger.warning(f"    class-dump failed: {e}")
        return data

    def _analyze_with_ctypes(self, framework_path: Path) -> Dict[str, Any]:
        """Attempt to load framework and inspect via ObjC runtime (in a subprocess)"""
        
        # Only attempt this for System frameworks to avoid crashes
        if not str(framework_path).startswith("/System/"):
            return {"method": "ctypes", "status": "skipped_unsafe"}

        # Get binary path
        scanner = FrameworkScanner()
        binary_path = scanner.get_binary_path(framework_path)
        if not binary_path:
            return {"method": "ctypes", "status": "skipped_no_binary"}

        # Create a small script to run in subprocess
        script = f"""
import ctypes
import sys

try:
    # RTLD_LAZY = 1
    ctypes.CDLL("{str(binary_path)}", mode=1)
    print("loaded")
except OSError:
    print("load_failed")
except Exception as e:
    print(f"error: {{e}}")
"""
        
        try:
            # Run the script in a separate process
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                timeout=5  # Short timeout for loading
            )
            
            output = result.stdout.strip()
            if result.returncode != 0:
                # Subprocess crashed (likely assertion failure or segfault)
                return {
                    "method": "ctypes", 
                    "status": "crashed", 
                    "error": "Subprocess crashed (likely +load assertion)"
                }
            
            if output == "loaded":
                return {"method": "ctypes", "status": "loaded"}
            elif output == "load_failed":
                return {"method": "ctypes", "status": "load_failed"}
            else:
                return {"method": "ctypes", "status": "error", "error": output}
                
        except subprocess.TimeoutExpired:
            return {"method": "ctypes", "status": "timeout"}
        except Exception as e:
            logger.warning(f"    Runtime analysis failed: {e}")
            return {"method": "ctypes", "status": "error", "error": str(e)}


class AIDocumenter:
    """Layer 4: AI Documentation (Basic Placeholder)"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, framework_name: str, data: Dict[str, Any]):
        # Save raw JSON data
        json_file = self.output_dir / f"{framework_name}.json"
        with open(json_file, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"  [Layer 4] Saved data to {json_file}")
        
        # Generate Markdown
        md_content = self._generate_simple_markdown(framework_name, data)
        
        # Save Markdown file
        # output_dir is 'data/', so parent is root. We want 'content/docs/'
        md_file = self.output_dir.parent / "content" / "docs" / f"{framework_name}.md"
        md_file.parent.mkdir(parents=True, exist_ok=True)
        with open(md_file, "w") as f:
            f.write(md_content)
            
    def _generate_simple_markdown(self, name: str, data: Dict[str, Any]) -> str:
        md = []
        md.append(f"---\ntitle: {name}\nweight: 1\n---\n")
        
        md.append("## Raw Data\n")
        md.append(f"Full analysis data is available in [`data/{name}.json`](../../data/{name}.json).\n")
        
        md.append("## Summary\n")
        md.append("```json")
        # Create a summary dict to avoid dumping huge strings
        summary = {
            "binary_path": data.get("binary_path"),
            "static": {
                "classes_count": len(data.get("static", {}).get("classes", [])),
                "swift_enabled": data.get("static", {}).get("swift_metadata", {}).get("is_swift", False),
            },
            "usage": {
                "used_by_count": len(data.get("usage", {}).get("used_by", []))
            },
            "runtime": data.get("runtime")
        }
        md.append(json.dumps(summary, indent=2))
        md.append("```\n")
        
        return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Deapplefy - Apple Private Framework Documentation Generator")
    parser.add_argument("--output", "-o", type=Path, default=Path("data"), help="Output directory for JSON data")
    parser.add_argument("--limit", "-l", type=int, default=0, help="Limit frameworks (0=all)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    # Components
    scanner = FrameworkScanner()
    static_analyzer = StaticAnalyzer()
    usage_analyzer = UsageAnalyzer()
    runtime_analyzer = RuntimeAnalyzer()
    ai_documenter = AIDocumenter(args.output)
    
    # Scan
    frameworks = scanner.scan()
    if not frameworks:
        return 1
        
    processed = 0
    for framework in frameworks:
        if args.limit > 0 and processed >= args.limit:
            break
            
        binary_path = scanner.get_binary_path(framework)
        if not binary_path:
            logger.warning(f"Skipping {framework.name}: No binary found")
            continue
            
        logger.info(f"Processing {framework.name}...")
        
        # Collect data from all layers
        data = {
            "framework": framework.name,
            "binary_path": str(binary_path)
        }
        
        # Layer 1
        data["static"] = static_analyzer.analyze(framework, binary_path)
        
        # Layer 2
        data["usage"] = usage_analyzer.analyze(framework.stem, data["static"])
        
        # Layer 3
        data["runtime"] = runtime_analyzer.analyze(framework)
        
        # Layer 4
        ai_documenter.generate(framework.stem, data)
        
        processed += 1
        
    logger.info(f"Processed {processed} frameworks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
