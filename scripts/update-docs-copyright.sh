#!/bin/bash
# Update copyright notices in all documentation files
# Author: CertifiedSlop

set -e

DOCS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs"

echo "Updating copyright notices in documentation files..."

# Function to add author line if not present
add_author_if_missing() {
    local file="$1"
    if ! grep -q "Author:" "$file" && ! grep -q "Author: CertifiedSlop" "$file"; then
        # Add author line after the title (first # line)
        sed -i '0,/^# /s/^# \(.*\)$/# \1\n\n**Author:** CertifiedSlop/' "$file"
        echo "  Added author to: $file"
    fi
}

# Function to add copyright footer if not present
add_copyright_if_missing() {
    local file="$1"
    if ! grep -q "© 2026 CertifiedSlop" "$file"; then
        echo "" >> "$file"
        echo "---" >> "$file"
        echo "" >> "$file"
        echo "&copy; 2026 CertifiedSlop. All rights reserved." >> "$file"
        echo "  Added copyright to: $file"
    fi
}

# Update all markdown files in docs/
find "$DOCS_DIR" -name "*.md" -type f | while read -r file; do
    add_author_if_missing "$file"
    add_copyright_if_missing "$file"
done

echo "Documentation copyright update complete!"
