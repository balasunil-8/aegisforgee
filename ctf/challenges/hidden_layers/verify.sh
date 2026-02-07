#!/bin/bash
# Quick verification script for HIDDEN_LAYERS challenge

echo "========================================"
echo "HIDDEN_LAYERS Challenge Verification"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "challenge.py" ]; then
    echo "❌ Error: Run this script from the hidden_layers directory"
    exit 1
fi

echo "📁 Checking directory structure..."
REQUIRED_FILES=(
    "README.md"
    "challenge.json"
    "challenge.py"
    "artifacts/mystery_image.png"
    "artifacts/instructions.txt"
    "artifacts/stego_tool_guide.md"
    "solution/SOLUTION.md"
    "solution/solve.py"
    "solution/solve_manual.md"
    "solution/hints.json"
    "tests/test_hidden_layers.py"
)

ALL_PRESENT=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ Missing: $file"
        ALL_PRESENT=false
    fi
done

if [ "$ALL_PRESENT" = false ]; then
    echo ""
    echo "❌ Some files are missing. Run: python3 challenge.py"
    exit 1
fi

echo ""
echo "🔍 Verifying image file..."
if file artifacts/mystery_image.png | grep -q "PNG image"; then
    SIZE=$(stat -f%z "artifacts/mystery_image.png" 2>/dev/null || stat -c%s "artifacts/mystery_image.png")
    echo "  ✅ Valid PNG image (${SIZE} bytes)"
else
    echo "  ❌ Invalid or missing image file"
    exit 1
fi

echo ""
echo "🧪 Running test suite..."
if python3 -m pytest tests/test_hidden_layers.py -q 2>&1 | grep -q "passed"; then
    echo "  ✅ All tests passed"
else
    echo "  ⚠️  Running with unittest..."
    if python3 tests/test_hidden_layers.py 2>&1 | grep -q "OK"; then
        echo "  ✅ All tests passed"
    else
        echo "  ❌ Some tests failed"
    fi
fi

echo ""
echo "🔓 Testing flag extraction..."
FLAG=$(python3 solution/solve.py artifacts/mystery_image.png 2>&1 | grep "HQX{" | tail -1 | grep -o "HQX{[^}]*}")
EXPECTED="HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"

if [ "$FLAG" = "$EXPECTED" ]; then
    echo "  ✅ Flag extracted successfully: $FLAG"
else
    echo "  ❌ Flag extraction failed"
    echo "     Expected: $EXPECTED"
    echo "     Got: $FLAG"
    exit 1
fi

echo ""
echo "========================================"
echo "✅ All verifications passed!"
echo "========================================"
echo ""
echo "📦 Challenge is ready for deployment!"
echo ""
echo "Distribution files for participants:"
echo "  - artifacts/mystery_image.png"
echo "  - artifacts/instructions.txt"
echo "  - artifacts/stego_tool_guide.md"
echo "  - README.md"
echo ""
echo "Flag: $EXPECTED"
echo ""
