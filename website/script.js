const header = document.querySelector(".site-header");

function updateHeader() {
  header?.setAttribute("data-elevated", String(window.scrollY > 24));
}

async function updateReleaseMetadata() {
  try {
    const response = await fetch("./release.json", { cache: "no-store" });
    if (!response.ok) {
      return;
    }

    const release = await response.json();

    if (release.version) {
      document.querySelectorAll("[data-release-version]").forEach((element) => {
        element.textContent = release.version;
      });
    }

    const status = document.querySelector("[data-release-status]");
    if (status && release.status) {
      status.textContent = release.status;
    }

    const releaseLink = document.querySelector("[data-release-url]");
    if (releaseLink && release.releaseUrl) {
      releaseLink.setAttribute("href", release.releaseUrl);
    }

    const sourceLink = document.querySelector("[data-source-url]");
    if (sourceLink && release.sourceUrl) {
      sourceLink.setAttribute("href", release.sourceUrl);
    }
  } catch {
    // Keep the static HTML fallback if release metadata is unavailable.
  }
}

updateHeader();
updateReleaseMetadata();
window.addEventListener("scroll", updateHeader, { passive: true });
