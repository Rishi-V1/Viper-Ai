(function () {
  const root = document.documentElement;
  const key = "blueshield-theme";
  let stored = "light"; // white & gold is the default look
  try {
    stored = localStorage.getItem(key) || "light";
  } catch (e) {
    /* storage unavailable, keep default */
  }
  root.setAttribute("data-bs-theme", stored);

  const btn = document.getElementById("theme-toggle");
  if (btn) {
    btn.addEventListener("click", function () {
      const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", next);
      try {
        localStorage.setItem(key, next);
      } catch (e) {
        /* ignore */
      }
    });
  }
})();
