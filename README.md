# Clean Sweep - WordPress Maintenance Toolkit

A simple toolkit for basic WordPress cleanup and maintenance tasks. Provides malware scanning, plugin management, core file updates, and file operations for WordPress administrators.

## Features

### 🔍 Malware Scanning
- Basic pattern-based malware detection
- Database scanning for suspicious content
- File scanning with common malware signatures

### 📦 Plugin Management
- Reinstall WordPress.org plugins with latest versions
- Automatic backup before changes
- Plugin verification after installation

### 🔄 Core File Management
- Download and replace WordPress core files
- Preserve wp-config.php and wp-content directory
- Backup existing core files before replacement

### 📁 File Operations
- Upload and extract ZIP files
- Drag & drop interface
- Extract to WordPress directories (plugins, themes, uploads, etc.)

## ✨ Features

- **Web Interface**: Browser-based tool with tabbed interface
- **Progress Tracking**: Real-time updates during operations
- **AJAX Support**: No page refreshes during long operations
- **Batch Processing**: Handles large operations in manageable chunks
- **Backup Creation**: Automatic backups before making changes
- **Memory Efficient**: Optimized for shared hosting environments
- **Cross-Platform**: Works in web browsers and command line
- **PHP 7.0+ Compatible**: Supports modern PHP versions

## 🚀 Quick Start

### Web Browser (Recommended)
1. **Upload**: Copy the entire `clean-sweep/` folder to your WordPress root directory
2. **Access**: Navigate to `http://yoursite.com/clean-sweep/clean-sweep.php`
3. **Use**: Select the tool you need from the tabbed interface
4. **Clean Up**: Use the cleanup tool to remove the toolkit when finished

### Command Line
```bash
# Navigate to WordPress root
cd /path/to/wordpress

# Run specific operations
php clean-sweep/clean-sweep.php
```

## 🛠️ Available Tools

### 1. 🛡️ WordPress Core Re-installation
- Downloads and installs clean WordPress core files
- Preserves `wp-config.php` and `/wp-content` directory
- Creates backup of existing core files
- Real-time progress tracking with AJAX

### 2. 📦 Plugin Management
- **Analysis Phase**: Scans all plugins and identifies WordPress.org vs custom plugins
- **Re-installation Phase**: Downloads latest versions from WordPress.org
- **Automatic Backup**: Creates timestamped backups before changes
- **Verification**: Confirms successful installation and accessibility

### 3. 📁 File Upload & Extraction
- Upload multiple ZIP files simultaneously
- Extract to any WordPress directory (plugins, themes, uploads, etc.)
- Drag & drop interface with progress tracking
- Safety checks and file validation

### 4. 🔍 Database Scanning
- Scan database tables for suspicious content
- Identify potential security issues
- Generate reports for manual review

### 5. � Malware Scanning
- Pattern-based malware detection
- File scanning with common signatures
- Basic security analysis

### 6. �🗑️ Cleanup Tool
- Removes all Clean Sweep files and directories
- Attempts to delete the main toolkit folder
- Leaves no trace when finished

## 📋 Requirements

- **PHP**: 7.0 or higher (7.x and 8.x recommended)
- **WordPress**: 6.0 or higher
- **Permissions**: Write access to WordPress directories
- **Internet**: Required for downloading WordPress core and plugins
- **Web Server**: Apache/Nginx with PHP support

## 🔒 Safety & Best Practices

### Before Using:
- ✅ **Complete backups**: Database, files, and offsite storage
- ✅ **Test environment**: Use staging/dev environment first
- ✅ **File permissions**: Ensure web server can write to target directories
- ✅ **Monitor execution**: Watch progress and stop if issues arise

### During Operations:
- 📊 **Real-time monitoring**: AJAX progress updates show current status
- 🛑 **Error handling**: Operations abort safely on critical errors
- 📝 **Detailed logging**: All actions logged with timestamps (only during operations)

### After Completion:
- ✅ **Verify functionality**: Test your website thoroughly
- ✅ **Re-activate plugins**: Use WordPress admin to enable plugins
- ✅ **Security audit**: Change passwords, update components
- ✅ **Clean up**: Use the cleanup tool to remove the toolkit

## 📁 File Structure

```
clean-sweep/
├── clean-sweep.php          # Main entry point
├── config.php               # Configuration constants
├── utils.php                # Utility functions
├── wordpress-api.php        # WordPress API wrappers
├── ui.php                   # User interface components
├── display.php              # Display and rendering functions
├── README.md                # This documentation
├── LICENSE                  # GPL v2 license
├── assets/
│   ├── css/
│   │   └── style.css        # Interface styling
│   └── js/
│       ├── ajax.js          # AJAX functionality
│       ├── core.js          # Core operations
│       ├── ui.js            # UI interactions
│       ├── upload.js        # File upload handling
│       └── reinstall.js     # Re-installation logic
├── features/
│   ├── core-reinstall.php   # WordPress core re-installation
│   ├── plugin-reinstall.php # Plugin management
│   ├── zip-extract.php      # File extraction
│   └── database-scan.php    # Database scanning
├── backups/                 # Auto-generated backup directories
└── logs/                    # Log files and progress tracking
```

## 📊 Output Files

### Log Files
- **Format**: `clean-sweep-log-YYYY-MM-DD-HH-II-SS.txt`
- **Location**: `clean-sweep/logs/` directory
- **Contents**: Detailed timestamped logs of all operations

### Backup Directories
- **Format**: `backups/wp-core-backup-YYYY-MM-DD-HH-II-SS/` (core files)
- **Format**: `backups/plugins-backup-YYYY-MM-DD-HH-II-SS/` (plugins)
- **Location**: `clean-sweep/backups/` directory
- **Contents**: Complete backups before modifications

### Progress Files
- **Format**: `core_progress_*.progress`, `plugin_progress_*.progress`
- **Location**: `clean-sweep/logs/` directory
- **Purpose**: AJAX progress tracking (auto-cleaned)

## 🛡️ Security Features

- **Repository Validation**: Only processes files from trusted sources
- **File Permission Checks**: Validates write access before operations
- **AJAX Communication**: Secure client-server communication
- **Input Sanitization**: All user inputs validated and sanitized
- **Error Containment**: Operations fail safely without data loss

## 🔧 Architecture

Clean Sweep uses a modular architecture where each feature is handled by its own dedicated file. The main entry point (`clean-sweep.php`) coordinates all toolkit functions through a clean, organized codebase.

## 📜 License

This project is licensed under the **GNU General Public License Version 2** (GPL v2) - see the [LICENSE](LICENSE) file for details.

## ⚠️ Important Notes

- **Use at your own risk**: While designed for safety, always have backups
- **Test first**: Use on development/staging environments when possible
- **Monitor closely**: Watch progress and logs during execution
- **Clean up**: Always use the cleanup tool to remove the toolkit when finished

## 🐛 Troubleshooting

### Common Issues:

**"Could not find wp-load.php"**
- Ensure Clean Sweep folder is in WordPress root directory
- Check file permissions on WordPress core files

**"Directory not writable"**
- Fix permissions: `chmod 755 wp-content/`
- Ensure web server user has write access

**"Download failed"**
- Check internet connection and firewall settings
- Verify target repositories are accessible

**Script timeouts**
- Increase PHP `max_execution_time`
- Use command line for large operations
- Process in smaller batches

### Recovery:
- Restore from backup directories if needed
- Check log files for detailed error information
- Contact WordPress support for core issues

## 📞 Support

This toolkit is provided as-is for WordPress security assistance. For issues:

1. Check the troubleshooting section above
2. Review log files for error details
3. Test on a development environment first
4. Report issues with detailed information

---

**Clean Sweep** - Keeping WordPress installations secure and clean.
