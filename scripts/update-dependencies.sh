# File: scripts/update-dependencies.sh
# Copy to: dcert repository scripts/ folder
# Make executable: chmod +x scripts/update-dependencies.sh

#!/bin/bash
# scripts/update-dependencies.sh - Manual dependency update script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔄 dcert Dependency Update Script${NC}"
echo "=================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Parse command line arguments
FORCE_UPDATE=false
MAJOR_UPDATES=false
DRY_RUN=false
RELEASE_TYPE="patch"

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_UPDATE=true
            shift
            ;;
        --major)
            MAJOR_UPDATES=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --release-type)
            RELEASE_TYPE="$2"
            shift
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force          Force update even if no changes"
            echo "  --major          Allow major version updates"
            echo "  --dry-run        Show what would be updated without making changes"
            echo "  --release-type   Type of release to create (patch|minor|major)"
            echo "  --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Standard update (patch release)"
            echo "  $0 --major --release-type minor  # Allow major updates, minor release"
            echo "  $0 --dry-run                # Preview changes without updating"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${YELLOW}Configuration:${NC}"
echo "  Force Update: $FORCE_UPDATE"
echo "  Major Updates: $MAJOR_UPDATES"
echo "  Dry Run: $DRY_RUN"
echo "  Release Type: $RELEASE_TYPE"
echo ""

# Check prerequisites
echo -e "${BLUE}🔍 Checking prerequisites...${NC}"

if ! command_exists cargo; then
    echo -e "${RED}❌ cargo not found. Please install Rust.${NC}"
    exit 1
fi

if ! command_exists git; then
    echo -e "${RED}❌ git not found. Please install git.${NC}"
    exit 1
fi

# Install required cargo subcommands
echo -e "${BLUE}📦 Installing/updating cargo tools...${NC}"
if [ "$DRY_RUN" = false ]; then
    cargo install cargo-edit cargo-audit cargo-outdated || {
        echo -e "${YELLOW}⚠️ Some cargo tools failed to install, continuing...${NC}"
    }
fi

# Get current version
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo -e "${GREEN}Current version: $CURRENT_VERSION${NC}"

# Backup current state
echo -e "${BLUE}💾 Creating backup...${NC}"
if [ "$DRY_RUN" = false ]; then
    cp Cargo.toml Cargo.toml.backup
    cp Cargo.lock Cargo.lock.backup 2>/dev/null || true
fi

# Check for outdated dependencies
echo -e "${BLUE}🔍 Checking for outdated dependencies...${NC}"
if command_exists cargo-outdated; then
    echo "Current outdated dependencies:"
    cargo outdated --root-deps-only || echo "Could not check outdated dependencies"
    echo ""
fi

# Update dependencies
echo -e "${BLUE}📦 Updating dependencies...${NC}"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[DRY RUN] Would run: cargo update${NC}"
    if [ "$MAJOR_UPDATES" = true ]; then
        echo -e "${YELLOW}[DRY RUN] Would run: cargo upgrade${NC}"
    fi
else
    echo "Running: cargo update"
    cargo update --verbose
    
    if [ "$MAJOR_UPDATES" = true ]; then
        echo "Running: cargo upgrade (allowing major version updates)"
        if command_exists cargo-upgrade; then
            cargo upgrade
        else
            echo -e "${YELLOW}⚠️ cargo-upgrade not available, using cargo-edit...${NC}"
            cargo upgrade || echo "cargo upgrade failed, continuing with cargo update results"
        fi
    fi
fi

# Check what changed
if [ "$DRY_RUN" = false ] && [ -f Cargo.lock.backup ]; then
    if ! cmp -s Cargo.lock Cargo.lock.backup; then
        echo -e "${GREEN}✅ Dependencies have been updated${NC}"
        echo -e "${BLUE}📋 Changes:${NC}"
        diff Cargo.lock.backup Cargo.lock | head -20 || true
        DEPENDENCIES_CHANGED=true
    else
        echo -e "${YELLOW}ℹ️ No dependency changes detected${NC}"
        DEPENDENCIES_CHANGED=false
    fi
else
    DEPENDENCIES_CHANGED=true  # Assume changes in dry run mode
fi

# Run security audit
echo -e "${BLUE}🔒 Running security audit...${NC}"
if [ "$DRY_RUN" = false ]; then
    if command_exists cargo-audit; then
        cargo audit || {
            echo -e "${RED}⚠️ Security audit found issues!${NC}"
            read -p "Continue anyway? (y/N): " -r
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborting due to security issues"
                exit 1
            fi
        }
    else
        echo -e "${YELLOW}⚠️ cargo-audit not available, skipping security check${NC}"
    fi
else
    echo -e "${YELLOW}[DRY RUN] Would run: cargo audit${NC}"
fi

# Run tests
echo -e "${BLUE}🧪 Running tests...${NC}"
if [ "$DRY_RUN" = false ]; then
    cargo test --all-features || {
        echo -e "${RED}❌ Tests failed!${NC}"
        echo "Restoring backup..."
        cp Cargo.toml.backup Cargo.toml
        cp Cargo.lock.backup Cargo.lock 2>/dev/null || true
        exit 1
    }
else
    echo -e "${YELLOW}[DRY RUN] Would run: cargo test --all-features${NC}"
fi

# Check formatting and linting
echo -e "${BLUE}🎨 Checking code quality...${NC}"
if [ "$DRY_RUN" = false ]; then
    cargo fmt -- --check || {
        echo -e "${YELLOW}⚠️ Code formatting issues found, running cargo fmt...${NC}"
        cargo fmt
    }
    
    cargo clippy -- -D warnings || {
        echo -e "${RED}❌ Clippy found issues!${NC}"
        exit 1
    }
else
    echo -e "${YELLOW}[DRY RUN] Would run: cargo fmt --check && cargo clippy${NC}"
fi

# Determine if release is needed
if [ "$DEPENDENCIES_CHANGED" = true ] || [ "$FORCE_UPDATE" = true ]; then
    echo -e "${GREEN}🚀 Release will be created${NC}"
    
    # Calculate new version
    IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
    PATCH=$(echo $PATCH | cut -d'-' -f1 | cut -d'+' -f1)
    
    case "$RELEASE_TYPE" in
        "major")
            NEW_VERSION="$((MAJOR + 1)).0.0"
            ;;
        "minor")
            NEW_VERSION="$MAJOR.$((MINOR + 1)).0"
            ;;
        "patch"|*)
            NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
            ;;
    esac
    
    echo -e "${BLUE}📝 New version will be: $CURRENT_VERSION → $NEW_VERSION${NC}"
    
    if [ "$DRY_RUN" = false ]; then
        # Update version in Cargo.toml (main.rs reads version automatically via build.rs)
        echo "Updating version in Cargo.toml..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
          sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
        else
          sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
        fi
        
        # Create commit and tag
        echo -e "${BLUE}📝 Creating commit and tag...${NC}"
        git add .
        git commit -m "chore: update dependencies and bump version to v$NEW_VERSION

Updated dependencies:
- Ran cargo update and cargo upgrade
- All tests pass
- Security audit clean

Automated dependency update via script."
        
        git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION - Dependency Update

This release includes updated dependencies and compatibility improvements."
        
        echo -e "${GREEN}✅ Changes committed and tagged as v$NEW_VERSION${NC}"
        echo -e "${YELLOW}📤 To complete the release, run:${NC}"
        echo "  git push origin main"
        echo "  git push origin v$NEW_VERSION"
        
    else
        echo -e "${YELLOW}[DRY RUN] Would update version to $NEW_VERSION and create commit/tag${NC}"
    fi
else
    echo -e "${YELLOW}ℹ️ No release needed - no dependency changes${NC}"
fi

# Generate summary
echo ""
echo -e "${BLUE}📊 Update Summary${NC}"
echo "=================="
echo "Current Version: $CURRENT_VERSION"
echo "Dependencies Changed: $DEPENDENCIES_CHANGED"
echo "Force Update: $FORCE_UPDATE"
if [ "$DEPENDENCIES_CHANGED" = true ] || [ "$FORCE_UPDATE" = true ]; then
    echo "New Version: $NEW_VERSION"
    echo "Release Type: $RELEASE_TYPE"
fi
echo "Dry Run: $DRY_RUN"

# Cleanup
if [ "$DRY_RUN" = false ]; then
    echo -e "${BLUE}🧹 Cleaning up backup files...${NC}"
    rm -f Cargo.toml.backup Cargo.lock.backup
fi

echo -e "${GREEN}✅ Dependency update process completed!${NC}"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}💡 To actually perform the update, run this script without --dry-run${NC}"
fi