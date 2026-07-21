const header = document.querySelector(".site-header");

function updateHeader() {
  header?.setAttribute("data-elevated", String(window.scrollY > 24));
}

updateHeader();
window.addEventListener("scroll", updateHeader, { passive: true });
