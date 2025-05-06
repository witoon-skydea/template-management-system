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