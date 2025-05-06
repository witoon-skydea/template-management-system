// Main JavaScript for Template Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-important)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Handle input box clicks in document view
    var inputBoxHighlights = document.querySelectorAll('.input-box-highlight');
    if (inputBoxHighlights.length > 0) {
        var editModal = new bootstrap.Modal(document.getElementById('editInputModal'));
        
        inputBoxHighlights.forEach(function(highlight) {
            highlight.addEventListener('click', function() {
                var boxId = this.getAttribute('data-box-id');
                var boxLabel = this.getAttribute('data-box-label');
                var value = this.getAttribute('data-value');
                
                document.getElementById('inputBoxId').value = boxId;
                document.getElementById('inputLabel').value = boxLabel;
                document.getElementById('inputValue').value = value;
                
                editModal.show();
            });
        });
    }
    
    // Handle multi-select users for station assignment
    initMultiUserSelect();
});

// Function to confirm delete actions
function confirmDelete(message) {
    return confirm(message || 'Are you sure you want to delete this item?');
}

// Function to preview markdown content
function previewMarkdown(markdownText, targetElementId) {
    // This function would use a markdown parser to convert markdown to HTML
    // For simplicity, we'll just add a placeholder
    const targetElement = document.getElementById(targetElementId);
    if (targetElement) {
        targetElement.innerHTML = '<div class="alert alert-info">Markdown preview would be displayed here</div>';
    }
}

// Function to highlight syntax in code blocks
function highlightCodeBlocks() {
    // Check if highlight.js is loaded
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightBlock(block);
        });
    }
}

// Call highlight function if needed
if (document.querySelector('pre code')) {
    highlightCodeBlocks();
}

// Initialize multi-user selection functionality
function initMultiUserSelect() {
    const selectAllCheckbox = document.getElementById('selectAllUsers');
    if (!selectAllCheckbox) return; // Not on the user management page
    
    const userCheckboxes = document.querySelectorAll('.user-checkbox');
    const selectedUsersDiv = document.getElementById('selectedUsers');
    const selectedCountSpan = document.getElementById('selectedCount');
    const userIdsInput = document.getElementById('userIdsInput');
    const assignButton = document.getElementById('assignButton');
    
    // Function to update the selected users display
    function updateSelectedUsers() {
        const selectedUsers = [];
        const selectedIds = [];
        let count = 0;
        
        userCheckboxes.forEach(checkbox => {
            if (checkbox.checked) {
                count++;
                const userId = checkbox.value;
                // Find the username text from the table row
                const username = checkbox.closest('tr').querySelector('td:nth-child(3)').textContent.trim();
                
                selectedUsers.push(username);
                selectedIds.push(userId);
            }
        });
        
        if (selectedUsers.length > 0) {
            selectedUsersDiv.innerHTML = selectedUsers.map(name => 
                `<span class="badge bg-primary me-1 mb-1">${name}</span>`
            ).join('');
            assignButton.disabled = false;
        } else {
            selectedUsersDiv.innerHTML = '<p class="text-muted">No users selected</p>';
            assignButton.disabled = true;
        }
        
        selectedCountSpan.textContent = count;
        userIdsInput.value = selectedIds.join(',');
    }
    
    // Select all users
    selectAllCheckbox.addEventListener('change', function() {
        userCheckboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
        });
        updateSelectedUsers();
    });
    
    // Individual user selection
    userCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            // If any checkbox is unchecked, uncheck "Select All"
            if (!this.checked && selectAllCheckbox.checked) {
                selectAllCheckbox.checked = false;
            }
            // If all checkboxes are checked, check "Select All"
            else if (this.checked) {
                let allChecked = true;
                userCheckboxes.forEach(cb => {
                    if (!cb.checked) allChecked = false;
                });
                selectAllCheckbox.checked = allChecked;
            }
            updateSelectedUsers();
        });
    });
    
    // Form submission handling
    const assignForm = document.getElementById('assignUsersForm');
    if (assignForm) {
        assignForm.addEventListener('submit', function(e) {
            if (userIdsInput.value === '') {
                e.preventDefault();
                alert('Please select at least one user to assign');
                return false;
            }
        });
    }
}