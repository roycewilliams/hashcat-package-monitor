# Hashcat Package Monitor

Automated monitoring of Hashcat package changes across software repositories (as monitored by Repology) with RSS feed generation.

## Quick start

1. Fork this repository
2. Enable GitHub Pages (Settings → Pages → Deploy from branch: main, folder: /docs)
3. Enable GitHub Actions workflow permissions (Settings → Actions → General → Read and write permissions)
4. Wait for first automated run or trigger manually in Actions tab

## Your RSS feed

Once setup is complete, your RSS feed will be available at:
`https://[your-username].github.io/[your-repo-name]/hashcat-changes.xml`

## Features

- **Automated Monitoring**: Runs every 6 hours via GitHub Actions
- **RSS Feed Generation**: Auto-updates RSS feed with detected changes
- **State Tracking**: Remembers previous states to detect actual changes
- **Security Focus**: Monitors version, origversion, and status fields
- **Zero Maintenance**: Runs completely automated once configured

## Local testing
```bash
# Install dependencies
cpanm --installdeps .

# Run monitor manually
perl monitor_hashcat.pl

# Generate RSS feed
perl update_rss.pl latest_changes.txt docs/hashcat-changes.xml
```

## Live example
[My production instance](https://roycewilliams.github.io/hashcat-package-monitor/).
