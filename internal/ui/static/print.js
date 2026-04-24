document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('print-btn');
    if (btn) btn.addEventListener('click', function () { window.print(); });
});
