(function () {
  const COOKIE_NAME = "cookiesAccepted";
  const PRIVACY_URL = "https://legal.barknbondk9solutions.com/#privacy";

  function getMainDomain() {
    const hostname = window.location.hostname;
    const parts = hostname.split(".");
    if (parts.length >= 2) {
      return "." + parts.slice(-2).join(".");
    }
    return hostname;
  }
  const COOKIE_DOMAIN = getMainDomain();

  const wrapper = document.createElement("div");
  Object.assign(wrapper.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    pointerEvents: "none",
    zIndex: "1000"
  });
  document.body.appendChild(wrapper);

  // === Scroll-to-top button ===
  const scrollBtn = document.createElement("button");
  scrollBtn.textContent = "↑";
  scrollBtn.setAttribute("aria-label", "Scroll to top");
  scrollBtn.setAttribute("tabindex", "0");
  scrollBtn.setAttribute("title", "Scroll to top");
  scrollBtn.setAttribute("type", "button");
  wrapper.appendChild(scrollBtn);

  Object.assign(scrollBtn.style, {
    position: "fixed",
    left: "20px",
    top: "93%",
    transform: "translateY(-50%) translateX(-100px)",
    width: "55px",
    height: "55px",
    border: "none",
    borderRadius: "50%",
    background: "rgba(50, 50, 50, 0.6)",
    backdropFilter: "blur(6px)",
    color: "#fff",
    fontSize: "26px",
    fontWeight: "700",
    cursor: "pointer",
    opacity: "0",
    pointerEvents: "auto",
    transition: "opacity 0.4s ease, transform 0.4s ease",
    boxShadow: "0 4px 12px rgba(0,0,0,0.2)",
    zIndex: "1001"
  });

  let scrollVisible = false;

  function updateScrollButton() {
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const halfway = docHeight / 2;

    if (window.scrollY > halfway && !scrollVisible) {
      scrollBtn.style.opacity = "1";
      scrollBtn.style.transform = "translateY(-50%) translateX(0)";
      scrollVisible = true;
    } else if (window.scrollY === 0 && scrollVisible) {
      scrollBtn.style.opacity = "0";
      scrollBtn.style.transform = "translateY(-50%) translateX(-100px)";
      scrollVisible = false;
    }
  }

  window.addEventListener("scroll", updateScrollButton, { passive: true });

  scrollBtn.addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  scrollBtn.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") {
      e.preventDefault();
      scrollBtn.click();
    }
  });

  scrollBtn.addEventListener("mouseenter", () => {
    scrollBtn.style.background = "rgba(50, 50, 50, 0.8)";
    scrollBtn.style.transform = "translateY(-50%) translateX(0) scale(1.1)";
  });

  scrollBtn.addEventListener("mouseleave", () => {
    scrollBtn.style.background = "rgba(50, 50, 50, 0.6)";
    scrollBtn.style.transform = "translateY(-50%) translateX(0) scale(1)";
  });

  // === Cookie functions ===
  function setCookie(name, value, days, domain) {
    let expires = "";
    if (days) {
      const date = new Date();
      date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
      expires = "; expires=" + date.toUTCString();
    }
    let domainPart = domain ? "; domain=" + domain : "";
    document.cookie = name + "=" + value + expires + "; path=/" + domainPart;
  }

  function getCookie(name) {
    const cookies = document.cookie.split(";").map(c => c.trim());
    for (let c of cookies) {
      if (c.indexOf(name + "=") === 0) {
        return c.substring(name.length + 1);
      }
    }
    return null;
  }

  // === Cookie Consent Popup ===
  if (!getCookie(COOKIE_NAME)) {
    const cookiePopup = document.createElement("div");
    cookiePopup.setAttribute("role", "dialog");
    cookiePopup.setAttribute("aria-modal", "true");
    cookiePopup.setAttribute("aria-labelledby", "cookieConsentTitle");
    cookiePopup.setAttribute("aria-describedby", "cookieConsentDesc");
    cookiePopup.setAttribute("tabindex", "-1");

    cookiePopup.innerHTML = `
      <div id="cookieConsentDesc" style="flex:1; font-size:16px; line-height:1.5; text-align:center; color:#fff;">
        <strong id="cookieConsentTitle" style="position:absolute; left:-9999px;">Cookie Consent Notice</strong>
        This website may use cookies and other trackers to enhance your browsing experience, analyze site usage, and provide relevant advertising. Cookies do not collect personal information unless you provide it voluntarily through forms. Please review our
        <a href="${PRIVACY_URL}" target="_blank" rel="noopener noreferrer" style="color:#fff; text-decoration:underline;">Privacy Policy</a>
        to understand how your information is used and protected.
      </div>
      <button id="acceptCookies" type="button" aria-label="Accept Cookies">Accept</button>
    `;
    wrapper.appendChild(cookiePopup);

    Object.assign(cookiePopup.style, {
      position: "fixed",
      top: "50%",
      left: "50%",
      transform: "translate(-50%, -50%) scale(0.8)",
      width: "90%",
      maxWidth: "400px",
      background: "rgba(50, 50, 50, 0.95)",
      color: "#fff",
      padding: "20px",
      borderRadius: "12px",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "sans-serif",
      boxSizing: "border-box",
      boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
      transition: "transform 0.4s ease, opacity 0.4s ease",
      opacity: "0",
      pointerEvents: "auto",
      zIndex: "1002"
    });

    const acceptBtn = cookiePopup.querySelector("#acceptCookies");
    Object.assign(acceptBtn.style, {
      background: "#4CAF50",
      color: "#fff",
      border: "none",
      padding: "12px 25px",
      borderRadius: "8px",
      cursor: "pointer",
      fontWeight: "700",
      fontSize: "16px",
      marginTop: "15px"
    });

    acceptBtn.addEventListener("mouseenter", () => {
      acceptBtn.style.background = "#45a049";
    });
    acceptBtn.addEventListener("mouseleave", () => {
      acceptBtn.style.background = "#4CAF50";
    });

    // Keyboard activation
    acceptBtn.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") {
        e.preventDefault();
        acceptBtn.click();
      }
    });

    setTimeout(() => {
      cookiePopup.style.opacity = "1";
      cookiePopup.style.transform = "translate(-50%, -50%) scale(1)";
      cookiePopup.focus(); // Set focus for screen readers
    }, 400);

    acceptBtn.addEventListener("click", () => {
      setCookie(COOKIE_NAME, "true", 365, COOKIE_DOMAIN);
      cookiePopup.style.opacity = "0";
      cookiePopup.style.transform = "translate(-50%, -50%) scale(0.8)";
      setTimeout(() => cookiePopup.remove(), 400);
    });
  }
})();
