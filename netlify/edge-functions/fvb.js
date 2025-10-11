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
<title>BarkNBondK9Solutions, LLC | Mobile Dog Training Miami-Dade</title>

<meta name="description" content="BarkNBondK9Solutions, LLC provides professional mobile dog training in Miami-Dade County. Services include puppy training, obedience, behavioral coaching, leash training, and more—right at your home.">
<meta name="keywords" content="mobile dog training Miami-Dade,dog trainer Miami,in-home dog training,puppy training Miami,obedience training Miami,behavioral dog training,private dog training,BarkNBondK9Solutions,dog training near me,dog obedience classes,dog behaviorist Miami,leash training,puppy socialization,dog recall training,housebreaking dogs,dog agility training,dog training services Miami-Dade,mobile puppy trainer,certified dog trainer Miami,professional dog trainer,dog obedience lessons,dog training consultation">
<meta name="robots" content="index, follow">

<!-- Open Graph / Social Sharing -->
<meta property="og:title" content="BarkNBondK9Solutions | Mobile Dog Training Miami-Dade">
<meta property="og:description" content="Professional mobile dog training in Miami-Dade County. Puppy training, obedience, behavioral coaching, and more—right at your home.">
<meta property="og:image" content="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png">
<meta property="og:url" content="https://barknbondk9solutions.com">
<meta property="og:type" content="website">
<meta property="og:site_name" content="BarkNBondK9Solutions">
<meta property="og:locale" content="en_US">
<meta property="og:image:alt" content="BarkNBondK9Solutions logo with a happy dog">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">

<!-- Twitter Card -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="BarkNBondK9Solutions | Mobile Dog Training Miami-Dade">
<meta name="twitter:description" content="Professional mobile dog training in Miami-Dade County. Puppy training, obedience, behavioral coaching, and more—right at your home.">
<meta name="twitter:image" content="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png">
<meta name="twitter:image:alt" content="BarkNBondK9Solutions logo with a happy dog">
<meta name="twitter:site" content="@BarkNBondK9Solutions">
<meta name="twitter:creator" content="@BarkNBondK9Solutions">

<style>
html, body {
  font-family: Arial, sans-serif;
  background: #f9f9f9;
  color: #333;
  margin: 0;
  padding: 0;
  overflow-y: auto;
}
.container {
  max-width: 1000px;
  margin: 20px auto;
  padding: 20px;
  background: #fff;
  border-radius: 12px;
  box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}
.logo {
  max-width: 180px;
  margin: 20px auto;
  display: block;
}
h1, h2, h3 {
  color: #222;
  margin: 10px 0;
}
h1 { font-size: 1.8em; }
h2 { font-size: 1.4em; margin-top: 30px; text-align:center; }
h3 { font-size: 1.2em; }
p { font-size: 1em; line-height: 1.5; margin-bottom: 15px; }
.highlight { color: #e74c3c; font-weight: bold; }
footer { margin-top: 30px; font-size: 0.9em; color: #666; text-align: center; }
.card-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin-top: 20px;
}
.card {
  background: #fafafa;
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 2px 10px rgba(0,0,0,0.08);
  transition: transform 0.2s;
}
.card:hover { transform: translateY(-5px); }
.card img { width: 100%; display: block; height: 150px; object-fit: cover; }
.card-content { padding: 10px; text-align: left; }
a { color: #e74c3c; text-decoration: none; word-break: break-word; }
@media (max-width: 768px) {
  h1 { font-size: 1.5em; }
  h2 { font-size: 1.2em; }
  h3 { font-size: 1em; }
  .card img { height: 120px; }
  .container { padding: 15px; }
}
@media (max-width: 480px) {
  h1 { font-size: 1.3em; }
  h2 { font-size: 1em; }
  h3 { font-size: 0.95em; }
  .card img { height: 100px; }
}
</style>
</head>
<body>
<div class="container" id="access-container">
  <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png" class="logo" alt="Logo" draggable="false">

  <h1>Access Limited</h1>
  <p>Thank you for visiting <span class="highlight">BarkNBondK9Solutions, LLC</span>. We are a Florida-based dog training company providing professional services in <span class="highlight">Miami-Dade County</span>.</p>
  <p>If you are outside Florida or using a VPN/proxy, access to some parts of the site may be restricted.</p>

  <p><strong>Contact Us:</strong><br>
    📞 <a href="tel:8336584388">833-658-4388</a><br>
    📧 <a href="mailto:info@barknbondk9solutions.com">info@barknbondk9solutions.com</a><br>
    Hours: Mon–Fri 8am–5pm | Sat 8am–12pm | Sun Closed
  </p>

  <h2>Our Dog Training Services</h2>
  <div class="card-container">
    <div class="card">
      <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/70673692664__08abe4ce-bb42-48de-b11f-f850b6b365ae-AE07oge8E9cDwkj5.jpeg" alt="Puppy Training">
      <div class="card-content">
        <h3>Puppy Training</h3>
        <p>Positive foundational training for your puppy's success at home.</p>
      </div>
    </div>
    <div class="card">
      <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/img_7722-AwvDD0L1r3cJWkrN.jpeg" alt="Obedience Training">
      <div class="card-content">
        <h3>Basic Obedience</h3>
        <p>Teach your dog essential commands and communication skills.</p>
      </div>
    </div>
    <div class="card">
      <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/puppy-5413165_1280-Awv4eXMqlXhzn846.jpg" alt="Behavior Training">
      <div class="card-content">
        <h3>Behavior Modification</h3>
        <p>Address unwanted behaviors like barking, jumping, and chewing.</p>
      </div>
    </div>
    <div class="card">
      <img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/dog-9295650_1280-A3Q2xZw1eMFEjey3.jpg" alt="Advanced Training">
      <div class="card-content">
        <h3>Advanced Skills</h3>
        <p>Specialized training to take your dog’s skills to the next level.</p>
      </div>
    </div>
  </div>

  <footer>&copy; <span id="currentYear"></span> BarkNBondK9Solutions, LLC | Serving dog owners throughout Miami-Dade County</footer>
</div>

<script>
document.getElementById('currentYear').textContent = new Date().getFullYear();

// Anti-copy / anti-inspect
document.addEventListener('copy',e=>e.preventDefault());
document.addEventListener('cut',e=>e.preventDefault());
document.addEventListener('paste',e=>e.preventDefault());
document.addEventListener('selectstart',e=>e.preventDefault());
document.addEventListener('contextmenu',e=>e.preventDefault());
document.addEventListener('keydown',e=>{
  if(e.ctrlKey && ['s','p','c','x','a','u'].includes(e.key.toLowerCase())){e.preventDefault(); alert("Action disabled.");}
  if(e.key==='PrintScreen'){navigator.clipboard.writeText(''); alert("Screenshots disabled.");}
});
document.querySelectorAll('img').forEach(img=>img.setAttribute('draggable','false'));
document.addEventListener('touchstart',e=>e.preventDefault(),{passive:false});
document.addEventListener('gesturestart',e=>e.preventDefault());
(function(){
  const devtools={open:false};
  const threshold=160;
  setInterval(()=>{
    const w=window.outerWidth-window.innerWidth;
    const h=window.outerHeight-window.innerHeight;
    if(w>threshold||h>threshold){
      if(!devtools.open){
        devtools.open=true;
        alert("DevTools detected! Page actions are disabled.");
        document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>";
      }
    } else devtools.open=false;
  },500);
  window.onkeydown=e=>{
    if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))){
      e.preventDefault();
      alert("DevTools shortcuts disabled.");
    }
  };
  window.addEventListener('resize',()=>{
    if(window.outerWidth-window.innerWidth>threshold||window.outerHeight-window.innerHeight>threshold){
      document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>";
    }
  });
})();
</script>
</body>
</html>`;

const response = new Response(html, { 
  status: 200, 
  headers: { 
    "Content-Type": "text/html",
    "X-Robots-Tag": "index, follow",
    "Cache-Control": "public, max-age=0, s-maxage=60"
  } 
});
if (addVpnHeader) response.headers.set("X-VPN-Warning","true");
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
// Helper: Add security headers + SEO
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

  response.headers.set("X-Robots-Tag", "index, follow");

  return response;
}
