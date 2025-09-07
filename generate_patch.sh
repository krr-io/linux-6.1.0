#!/bin/bash

set -e  # Exit on any error

# Function to print colored output
print_info() {
    echo -e "\033[36m[INFO]\033[0m $1"
}

print_warning() {
    echo -e "\033[33m[WARNING]\033[0m $1"
}

print_error() {
    echo -e "\033[31m[ERROR]\033[0m $1"
}

# Check if we're in a git repository
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    print_error "Not in a git repository"
    exit 1
fi

# Get the total number of commits
total_commits=$(git rev-list --count HEAD)

# Calculate commits after the first one
commits_after_first=$((total_commits - 1))

if [ $commits_after_first -le 0 ]; then
    print_info "There's only one commit in this repository. Nothing to squash."
    exit 0
fi

# Get the current branch name
current_branch=$(git rev-parse --abbrev-ref HEAD)

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    print_warning "You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

print_info "Found $commits_after_first commits after the initial commit on branch '$current_branch'."
print_info "This will combine all commits after the first one into a single commit."

# Configuration
commit_message="Support KRR guest agent"
directories_to_remove=(
    "rr_scripts/process_trace.py"
    "rr_experiment_config"
    "rr_config_replay"
    "rr_scripts/"
    "generate_patch.sh"
    "README"
)

# Create a backup branch
backup_branch="${current_branch}_backup_$(date +%Y%m%d_%H%M%S)"
git branch "$backup_branch"
print_info "Created backup branch: $backup_branch"
git checkout -f $backup_branch

# Perform the squash
print_info "Combining commits..."
git reset --soft HEAD~$commits_after_first

# Remove specified directories from the staged changes
print_info "Removing specified directories from the final commit..."
for dir in "${directories_to_remove[@]}"; do
    if git ls-files --cached | grep -q "^${dir%/}"; then
        git reset HEAD -- "$dir" 2>/dev/null || true
        print_info "Removed '$dir' from staged changes"
    else
        print_info "Directory/file '$dir' not found in staged changes"
    fi
done

# Check if there are still changes to commit
if git diff --cached --quiet; then
    print_warning "No changes left to commit after removing specified directories."
    print_info "Restoring to original state..."
    git reset --hard "$backup_branch"
    git branch -D "$backup_branch"
    exit 1
fi

# Commit the squashed changes
git commit -m "$commit_message"
print_info "Done! All commits after the first one have been combined."

# Generate patch file
patch_file="$(git log --format="%f" -n 1).patch"
git format-patch HEAD~1 --stdout > "$patch_file"
print_info "Generated patch file: $patch_file"

# Show summary
print_info "Summary:"
echo "  - Original commits: $total_commits"
echo "  - Commits squashed: $commits_after_first"
echo "  - Backup branch: $backup_branch"
echo "  - Patch file: $patch_file"

git checkout -f $current_branch
# Optional: Ask if user wants to delete backup branch
read -p "Delete backup branch '$backup_branch'? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git branch -D "$backup_branch"
    print_info "Deleted backup branch: $backup_branch"
fi

exit 0
