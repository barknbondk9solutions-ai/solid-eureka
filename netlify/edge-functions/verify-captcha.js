export default async (request) => {
  if (request.method !== "POST") {

    if (request.method === "OPTIONS") {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}
    return new Response(JSON.stringify({ success: false, error: "Only POST allowed" }), {
      status: 405,
      headers: { "content-type": "application/json" }
    });
  }

  try {
    const body = await request.json();
    const token = body?.token;
    if (!token) {
      return new Response(JSON.stringify({ success: false, error: "Missing token" }), {
        status: 400,
        headers: { "content-type": "application/json" }
      });
    }

    const RECAPTCHA_SECRET_KEY = Deno.env.get("RECAPTCHA_SECRET_KEY");
    if (!RECAPTCHA_SECRET_KEY) throw new Error("Missing RECAPTCHA_SECRET_KEY");

    // Verify with Google
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${encodeURIComponent(RECAPTCHA_SECRET_KEY)}&response=${encodeURIComponent(token)}`
    });
    const data = await response.json();

    if (!data.success || data.score < 0.4) { // optional: score threshold
      return new Response(JSON.stringify({ success: false }), {
        status: 403,
        headers: { "content-type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });

  } catch (err) {
    console.error("Captcha verification error:", err);
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  }
};
