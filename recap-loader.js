(function() {
  const SITE_KEY = "6Lfb--wrAAAAAAgJc8REQQOaKPwRk0TY5rC5s95N";
  const FLAG_KEY = "__recap_ok";

  // Already verified
  if (sessionStorage.getItem(FLAG_KEY) === "1") return;

  // Load reCAPTCHA script
  const script = document.createElement("script");
  script.src = `https://www.google.com/recaptcha/api.js?render=${SITE_KEY}`;
  script.async = true;
  script.defer = true;

  script.onload = () => {
    grecaptcha.ready(() => {
      grecaptcha.execute(SITE_KEY, { action: "homepage" }).then(token => {
        fetch(`${location.origin}/verify-captcha`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token })
        })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            sessionStorage.setItem(FLAG_KEY, "1");
            console.log("CAPTCHA verified successfully");
          } else {
            console.warn("CAPTCHA verification failed");
          }
        })
        .catch(err => console.error("CAPTCHA fetch error:", err));
      });
    });
  };

  script.onerror = () => console.error("Failed to load reCAPTCHA script");
  document.head.appendChild(script);
})();
