// Keyboard shortcut for the search field in the top bar: "/" or Ctrl+K (Cmd+K) puts the cursor in it from anywhere,
// except while typing in another field. Bound once, no inline handlers (CSP).
(function () {
    "use strict";

    function typing(target) {
        if (!target) return false;
        var tag = target.tagName;
        return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
    }

    document.addEventListener("keydown", function (e) {
        var shortcut = (e.key === "/" && !typing(e.target)) || ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K"));
        if (!shortcut) return;
        var input = document.querySelector("#vy-global-search input");
        if (!input) return;
        e.preventDefault();
        input.focus();
        input.select();
    });
})();
