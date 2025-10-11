export default async (request, context) => {
  try {
    const userAgent = (request.headers.get("user-agent") || "").toLowerCase();
    const clientIP = context.clientAddress;

    // ==========================
    // 1️⃣ SEO BOT WHITELIST
    // ==========================
    const seoBots = [
      "googlebot","googlebot-image","googlebot-video","googlebot-news",
      "bingbot","slurp","duckduckbot","baiduspider","yandex",
      "facebookexternalhit","twitterbot","linkedinbot",
      "semrushbot","ahrefsbot"
    ];

    if (seoBots.some(bot => userAgent.includes(bot))) {
      const seoResponse = await context.next();
      return addSecurityHeaders(seoResponse);
    }

    // ==========================
    // 2️⃣ GEO / VPN / DATACENTER CHECK
    // ==========================
    let showAccessRestricted = false; 
    let addVpnHeader = false;

    const country = context.geo?.country?.code || "";
    const state = context.geo?.subdivision?.code || "";

    if (country && (country !== "US" || state !== "FL")) {
      showAccessRestricted = true;
    }

if (clientIP) {
  const apiKey = Deno.env.get("IPAPI_API_KEY");
  if (apiKey) {
    try {
      const resp = await fetch(`https://api.ipapi.is/?q=${clientIP}&key=${apiKey}&fields=security,connection,asn,org,type,location`);
      if (resp.ok) {
        const data = await resp.json();

        // ✅ Extract country and state
        const country = data?.location?.country_code || data?.country_code || "";
        const state =
          data?.location?.region_code ||
          data?.location?.region ||
          data?.region_code ||
          data?.region_name ||
          "";

        const vpnFlag =
          Boolean(data?.security?.is_vpn) ||
          Boolean(data?.security?.is_proxy) ||
          Boolean(data?.security?.is_tor) ||
          Boolean(data?.security?.is_hosting) ||
          Boolean(
            data?.connection?.type &&
            [
              "hosting",
              "datacenter",
              "vpn",
              "vpnserver",
              "proxy",
              "residential",
              "business"
            ].some(t => data.connection.type.toLowerCase().includes(t))
          ) ||
          Boolean(data?.connection?.asn && /vpn|proxy|hosting|vps|datacenter/i.test(data.connection.asn)) ||
          Boolean(data?.org && /vpn|proxy|hosting|vps|datacenter/i.test(data.org.toLowerCase()));

        // ✅ Florida-only VPN detection
        if (country === "US" && state === "FL") {
          if (vpnFlag) {
            console.log("⚠️ VPN detected in Florida via API:", clientIP);
            addVpnHeader = true; 
          } else {
            console.log("✅ Florida visitor is clean:", clientIP);
          }
        }

        const suspiciousOrg = (
          (data?.asn?.name || data?.asn?.org || data?.org || data?.connection?.org || data?.connection?.autonomous_system_organization || "")
        ).toString().toLowerCase();

        const hostingKeywords = [
          "amazon","aws","amazonaws","google","microsoft","azure","digitalocean","linode","vultr",
          "hetzner","ovh","ovhcloud","packet","scaleway","oracle","leaseweb","softlayer","cloudflare",
          "aliyun","alibaba","bkcloud","contabo","rackspace","clouvider","colocrossing","servermania",
          "choopa","vpsnet","hivelocity","voxility","hexonet","hostwinds","turnkeyinternet","eukhost",
          "netcup","fastly","akamai","stackpath","keycdn","limelight","edgecast","cloudsigma","upcloud",
          "krypt","datacamp","layerhost","bandwagonhost","phoenixnap","psychz","ovh.ie","soyoustart","kimsufi",
          "dedipath","interserver","ionos","oneprovider","hostgator","bluehost","dreamhost","namecheap",
          "resellerclub","a2hosting","hostinger","wpengine","inmotion","liquidweb","greengeeks",
          "nordvpn","expressvpn","surfshark","cyberghost","privateinternetaccess","pia","protonvpn","windscribe",
          "vpnunlimited","hide.me","torguard","purevpn","ipvanish","vyprvpn","strongvpn","hotspotshield","hola",
          "urbanvpn","atlasvpn","mullvad","perfectprivacy","azirevpn","privado","slickvpn","ivpn","airvpn",
          "fastestvpn","hideipvpn","safervpn","vpnsecure","vpn.ac","zenmate","shieldvpn","goosevpn","rocketvpn",
          "ultravpn","unlocator","kasperskyvpn","avastvpn","bitdefendervpn","browsec","opera-vpn","guardianvpn",
          "totalvpn","okayfreedom","trust.zone","hideallip","seed4.me","vpnarea","supervpn","betternet","psiphon",
          "touchvpn","tunnelbear","xvpn","ultrasurf","thundervpn","melonvpn","snapvpn","securevpn",
          "proxy","tor","openvpn","pptp","l2tp","socks5","shadowsocks","anonine","smartproxy","residentialproxy",
          "brightdata","oxylabs","iproyal","packetstream","netnut","stormproxies","proxyhub","scraperapi",
          "proxyseller","myiphide","proxyrack","ipburger","smartdnsproxy","hidester","kproxy","proxysite",
          "megaproxy","zend2","freeproxy","sslproxy","openproxy","cloudproxy"
        ];

        const typeSuspicious = ["hosting","datacenter","business","vpn","proxy","residential"].some(t => {
          const typ = (data?.type || data?.connection?.type || "").toLowerCase();
          return typ.includes(t);
        });

        // Backup IP check
        try {
          const backupResp = await fetch(`https://ipinfo.io/${clientIP}/json`);
          if (backupResp.ok) {
            const backupData = await backupResp.json();
            const backupOrg = (backupData.org || "").toLowerCase();
            if (/vpn|proxy|vps|hosting|datacenter|network|cloud|colo/i.test(backupOrg)) {
              console.log("⚠️ Backup VPN/proxy detection:", backupOrg);
              return new Response(
                "Access not allowed from VPN/proxy/hosting provider (backup check).",
                { status: 403 }
              );
            }
          }
        } catch (backupErr) {
          console.error("Backup IP check failed:", backupErr);
        }

        if (hostingKeywords.some(k => suspiciousOrg.includes(k)) || typeSuspicious) {
          return new Response(
            "Access not allowed from high-risk VPN/proxy/hosting provider.",
            { status: 403 }
          );
        }
      }
    } catch (err) {
      console.error("VPN/proxy check failed:", err);
    }
  }
}
// ==========================
// 3️⃣ Show Access Restricted HTML
// ==========================
if (showAccessRestricted) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Restricted | BarkNBondK9Solutions, LLC</title>

<!-- SEO Meta -->
<meta name="description" content="BarkNBondK9Solutions, LLC offers professional mobile dog training in Miami-Dade County. Puppy training, obedience, behavioral training, leash training, and more—right in your home.">
<meta name="keywords" content="dog trainer Miami, dog training Miami-Dade, mobile dog training, in-home dog training, puppy trainer Miami, obedience training, behavioral dog training, leash training, puppy socialization, private dog trainer Miami, local dog trainer, certified dog trainer Miami-Dade, mobile obedience training, Miami dog behaviorist, dog recall training, housebreaking puppy, professional dog trainer Florida, BarkNBondK9Solutions Miami, dog training services Miami-Dade County, Miami, Coral Gables, Hialeah, Miami Beach, North Miami, South Miami, Kendall, Doral, Homestead, Aventura, Sunny Isles Beach, Bal Harbour, Surfside, Pinecrest">

<meta property="og:title" content="BarkNBondK9Solutions | Mobile Dog Training Miami-Dade">
<meta property="og:description" content="Professional mobile dog training in Miami-Dade County. Puppy training, obedience, behavioral coaching, and more—right at your home.">
<meta property="og:image" content="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png">
<meta property="og:url" content="https://barknbondk9solutions.com">
<meta property="og:type" content="website">

<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="BarkNBondK9Solutions | Mobile Dog Training Miami-Dade">
<meta name="twitter:description" content="Professional mobile dog training in Miami-Dade County. Puppy training, obedience, behavioral coaching, and more—right at your home.">
<meta name="twitter:image" content="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png">

<style>
  html, body {
    margin: 0;
    padding: 0;
    font-family: Arial, sans-serif;
    background: #f9f9f9;
    color: #333;
    overflow-x: hidden;
    -webkit-user-select: none;
    -ms-user-select: none;
    user-select: none;
  }
  .container {
    max-width: 900px;
    margin: 20px auto;
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
  }
  .logo {
    max-width: 180px;
    margin-bottom: 20px;
    pointer-events: none;
  }
  h1 {
    font-size: 2em;
    margin-bottom: 15px;
    color: #222;
  }
  p {
    font-size: 1.1em;
    line-height: 1.6;
    margin-bottom: 15px;
  }
  .highlight { color:#e74c3c; font-weight:bold; }
  footer { margin-top: 25px; font-size: 0.9em; color: #666; }
  /* Main page preview */
  .preview-section {
    margin-top: 30px;
    border-top: 1px solid #ddd;
    padding-top: 20px;
  }
  .preview-section h2 { margin-bottom: 15px; }
  .card-container { display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; }
  .card {
    background: #f5f5f5;
    border-radius: 8px;
    width: 260px;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
  }
  .card img { width: 100%; display: block; }
  .card-content { padding: 10px; }
  .card-content h3 { margin: 5px 0; font-size: 1.1em; }
  .card-content p { font-size: 0.95em; margin: 5px 0; }
</style>
</head>
<body>
<div class="container">
  <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png" class="logo" alt="Logo" draggable="false">
  <h1>Access Restricted</h1>
  <p>Thank you for visiting <span class="highlight">BarkNBondK9Solutions, LLC</span>. We are a Florida-based mobile dog training company serving <span class="highlight">Miami-Dade County</span>.</p>
  <p>If you are outside Florida or using a VPN/proxy, access to some parts of the site may be restricted.</p>

  <!-- ========================
       Optional Main Page Preview
  ======================== -->
  <div class="preview-section">
    <h2>Main Page Preview</h2>
    <div class="card-container">
      <div class="card">
        <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/70673692664__08abe4ce-bb42-48de-b11f-f850b6b365ae-AE07oge8E9cDwkj5.jpeg" alt="Puppy Training">
        <div class="card-content">
          <h3>Puppy Training</h3>
          <p>Set your puppy up for success with early foundational training using positive methods.</p>
        </div>
      </div>
      <div class="card">
        <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/img_7722-AwvDD0L1r3cJWkrN.jpeg" alt="Obedience Training">
        <div class="card-content">
          <h3>Basic Obedience</h3>
          <p>Teach your dog essential commands and build strong communication skills.</p>
        </div>
      </div>
      <div class="card">
        <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/puppy-5413165_1280-Awv4eXMqlXhzn846.jpg" alt="Behavior Training">
        <div class="card-content">
          <h3>Behavior Modification</h3>
          <p>Address unwanted behaviors like jumping, barking, and chewing in a trust-based way.</p>
        </div>
      </div>
      <div class="card">
        <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/dog-9295650_1280-A3Q2xZw1eMFEjey3.jpg" alt="Advanced Training">
        <div class="card-content">
          <h3>Advanced Skills</h3>
          <p>Take your dog's learning to the next level with specialized training modules.</p>
        </div>
      </div>
    </div>
  </div>

  <footer>&copy; <span id="currentYear"></span> BarkNBondK9Solutions, LLC | Serving dog owners throughout Miami-Dade County</footer>
</div>

<script>
document.getElementById('currentYear').textContent = new Date().getFullYear();

// Anti-copy / selection
document.addEventListener('copy', e=>e.preventDefault());
document.addEventListener('cut', e=>e.preventDefault());
document.addEventListener('paste', e=>e.preventDefault());
document.addEventListener('selectstart', e=>e.preventDefault());
document.addEventListener('contextmenu', e=>e.preventDefault());
document.addEventListener('keydown', e=>{
  if(e.ctrlKey && ['s','p','c','x','a','u'].includes(e.key.toLowerCase())){
    e.preventDefault(); alert("Action disabled.");
  }
  if(e.key === 'PrintScreen'){ navigator.clipboard.writeText(''); alert("Screenshots disabled."); }
});
document.querySelectorAll('img').forEach(img=>img.setAttribute('draggable','false'));

// DevTools detection
(function(){
  const devtools={open:false}; const threshold=160;
  setInterval(()=>{
    const w=window.outerWidth-window.innerWidth, h=window.outerHeight-window.innerHeight;
    if(w>threshold || h>threshold){
      if(!devtools.open){ devtools.open=true; alert("DevTools detected! Page actions are disabled."); document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>"; }
    } else devtools.open=false;
  },500);
  window.onkeydown = e => {
    if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))){ e.preventDefault(); alert("DevTools shortcuts disabled."); }
  };
  window.addEventListener('resize', ()=>{
    if(window.outerWidth-window.innerWidth>threshold || window.outerHeight-window.innerHeight>threshold){ document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>"; }
  });
})();

// Allow normal scrolling
document.addEventListener('touchstart', e => { if(e.touches.length>1)e.preventDefault(); }, {passive:false});
</script>
</body>
</html>`;

  const response = new Response(html, { status: 200, headers: { "Content-Type": "text/html" } });
  if(addVpnHeader) response.headers.set("X-VPN-Warning","true");
  return addSecurityHeaders(response);
}
    // ==========================
    // 4️⃣ Default: allow humans
    // ==========================
    const response = await context.next();
    if (addVpnHeader) response.headers.set("X-VPN-Warning","true");
    return addSecurityHeaders(response);

  } catch (err) {
    console.error("Edge Function error:", err);
    const response = await context.next();
    return addSecurityHeaders(response);
  }
};

// ==========================
// Helper: Add security headers
// ==========================
function addSecurityHeaders(response){
  response.headers.set("Strict-Transport-Security","max-age=63072000; includeSubDomains; preload");
  response.headers.set("X-Frame-Options","SAMEORIGIN");
  response.headers.set("X-Content-Type-Options","nosniff");
  response.headers.set("Referrer-Policy","strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy","geolocation=(), microphone=(), camera=()");
  response.headers.set("Content-Security-Policy",
    "default-src * data: blob: filesystem: about: ws: wss:; "+
    "script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "+
    "style-src * 'unsafe-inline' data: blob:; "+
    "img-src * data: blob:; "+
    "connect-src * data: blob:; "+
    "frame-src * data: blob:; "+
    "media-src * data: blob:; "+
    "font-src * data: blob:;"
  );
  return response;
}
