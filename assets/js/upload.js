// Clean Sweep - File Upload
// File upload and drag-drop functionality

// File upload handling for multiple files
let selectedFiles = [];

function handleMultipleFileUpload(files) {
    // Add new files to the selection
    for (let i = 0; i < files.length; i++) {
        const file = files[i];

        // Validate file type
        if (file.type === "application/zip" || file.name.toLowerCase().endsWith(".zip")) {
            // Check if file is already selected
            const existingIndex = selectedFiles.findIndex(f => f.name === file.name && f.size === file.size);
            if (existingIndex === -1) {
                selectedFiles.push(file);
            }
        }
    }

    updateFileQueueDisplay();
}

function updateFileQueueDisplay() {
    const fileQueue = document.getElementById("file-queue");
    const fileList = document.getElementById("file-list");
    const fileCount = document.getElementById("file-count");

    if (selectedFiles.length > 0) {
        fileQueue.style.display = "block";
        fileCount.textContent = selectedFiles.length;

        fileList.innerHTML = "";
        selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement("div");
            fileItem.className = "file-item";

            const sizeFormatted = formatFileSize(file.size);

            fileItem.innerHTML = `
                <div class="file-info">
                    <span class="file-icon">📁</span>
                    <div class="file-details">
                        <div class="file-name">${file.name}</div>
                        <div class="file-size">${sizeFormatted}</div>
                    </div>
                </div>
                <button type="button" class="remove-file" onclick="removeFile(${index})">Remove</button>
            `;

            fileList.appendChild(fileItem);
        });
    } else {
        fileQueue.style.display = "none";
    }
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateFileQueueDisplay();
}

function clearFileQueue() {
    selectedFiles = [];
    updateFileQueueDisplay();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Drag and drop functionality
document.addEventListener("DOMContentLoaded", function() {
    const uploadArea = document.getElementById("upload-area");
    if (uploadArea) {
        uploadArea.addEventListener("dragover", function(e) {
            e.preventDefault();
            uploadArea.classList.add("dragover");
        });

        uploadArea.addEventListener("dragleave", function(e) {
            e.preventDefault();
            uploadArea.classList.remove("dragover");
        });

        uploadArea.addEventListener("drop", function(e) {
            e.preventDefault();
            uploadArea.classList.remove("dragover");
            handleMultipleFileUpload(e.dataTransfer.files);
        });
    }
});

// Upload validation function for multiple files
function validateMultipleUpload() {
    if (selectedFiles.length === 0) {
        alert("Please select at least one ZIP file to upload.");
        return false;
    }

    // Validate all selected files
    for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles[i];
        if (!file.name.toLowerCase().endsWith(".zip") && file.type !== "application/zip") {
            alert(`File "${file.name}" is not a valid ZIP file. Please remove it and try again.`);
            return false;
        }
    }

    // Populate the file input with all selected files before form submission
    const fileInput = document.getElementById("zip-upload");
    const dt = new DataTransfer();

    for (let i = 0; i < selectedFiles.length; i++) {
        dt.items.add(selectedFiles[i]);
    }

    fileInput.files = dt.files;

    const fileCount = selectedFiles.length;
    const plural = fileCount > 1 ? "files" : "file";
    return confirm(`Are you sure you want to extract ${fileCount} ${plural}? Existing files with the same name will be overwritten.`);
}

// Malware removal toggle function
function toggleMalwareRemoval(checkbox) {
    const malwareTargets = document.getElementById("malware-targets");
    if (checkbox.checked) {
        malwareTargets.style.display = "block";
    } else {
        malwareTargets.style.display = "none";
    }
}

// Upload validation function (legacy for single file)
function validateUpload() {
    const fileInput = document.getElementById("zip-upload");
    if (!fileInput.files || fileInput.files.length === 0) {
        alert("Please select a ZIP file to upload.");
        return false;
    }

    const file = fileInput.files[0];
    if (!file.name.endsWith(".zip") && file.type !== "application/zip") {
        alert("Please select a valid ZIP file.");
        return false;
    }

    return confirm("Are you sure you want to extract this file? Existing files with the same name will be overwritten.");
}
