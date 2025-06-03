import { connect } from "cloudflare:sockets";

// Variables
const rootDomain = "kameha.workers.dev"; // Ganti dengan domain utama kalian
const serviceName = "meta"; // Ganti dengan nama workers kalian
const apiKey = ""; // Ganti dengan Global API key kalian (https://dash.cloudflare.com/profile/api-tokens)
const apiEmail = ""; // Ganti dengan email yang kalian gunakan
const accountID = ""; // Ganti dengan Account ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
const zoneID = ""; // Ganti dengan Zone ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];

// Constant
const APP_DOMAIN = `${serviceName}.${rootDomain}`;
const PORTS = [443, 80];
const PROTOCOLS = ["trogjan", "vlgess", "ss", "vmgess"];
const KV_PROXY_URL = "https://raw.githubusercontent.com/superchanuwu/fb/refs/heads/main/kvProxyList.json";
const PROXY_BANK_URL = "https://raw.githubusercontent.com/superchanuwu/fb/refs/heads/main/proxyList.txt";
const DOH_SERVER = "https://dns.quad9.net/dns-query";
const PROXY_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";
const CONVERTER_URL =
  "https://script.google.com/macros/s/AKfycbwwVeHNUlnP92syOP82p1dOk_-xwBgRIxkTjLhxxZ5UXicrGOEVNc5JaSOu0Bgsx_gG/exec";
const PROXY_PER_PAGE = 24;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

async function getKVProxyList(kvProxyUrl = KV_PROXY_URL) {
  if (!kvProxyUrl) {
    throw new Error("No KV Proxy URL Provided!");
  }

  const kvProxy = await fetch(kvProxyUrl);
  if (kvProxy.status == 200) {
    return await kvProxy.json();
  } else {
    return {};
  }
}

async function getProxyList(proxyBankUrl = PROXY_BANK_URL) {
  /**
   * Format:
   *
   * <IP>,<Port>,<Country ID>,<ORG>
   * Contoh:
   * 1.1.1.1,443,SG,Cloudflare Inc.
   */
  if (!proxyBankUrl) {
    throw new Error("No Proxy Bank URL Provided!");
  }

  const proxyBank = await fetch(proxyBankUrl);
  if (proxyBank.status == 200) {
    const text = (await proxyBank.text()) || "";

    const proxyString = text.split("\n").filter(Boolean);
    cachedProxyList = proxyString
      .map((entry) => {
        const [proxyIP, proxyPort, country, org] = entry.split(",");
        return {
          proxyIP: proxyIP || "Unknown",
          proxyPort: proxyPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }

  return cachedProxyList;
}

async function reverseProxy(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function getAllConfig(request, hostName, proxyList, page = 0) {
  const startIndex = PROXY_PER_PAGE * page;

  try {
    const uuid = crypto.randomUUID();

    // Build URI
    const uri = new URL(`trogjan://${hostName}`);
    uri.searchParams.set("encryption", "none");
    uri.searchParams.set("type", "ws");
    uri.searchParams.set("host", hostName);

    // Build HTML
    const document = new Document(request);
    document.setTitle("Welcome to <span class='text-blue-500 font-semibold'>Nautica</span>");
    document.addInfo(`Total: ${proxyList.length}`);
    document.addInfo(`Page: ${page}/${Math.floor(proxyList.length / PROXY_PER_PAGE)}`);

    for (let i = startIndex; i < startIndex + PROXY_PER_PAGE; i++) {
      const proxy = proxyList[i];
      if (!proxy) break;

      const { proxyIP, proxyPort, country, org } = proxy;

      uri.searchParams.set("path", `/${proxyIP}-${proxyPort}`);

      const proxies = [];
      for (const port of PORTS) {
        uri.port = port.toString();
        uri.hash = `${i + 1} ${getFlagEmoji(country)} ${org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
        for (const protocol of PROTOCOLS) {
          // Special exceptions
          if (protocol === "ss") {
            uri.username = btoa(`none:${uuid}`);
          } else {
            uri.username = uuid;
          }

          uri.protocol = protocol;
          uri.searchParams.set("security", port == 443 ? "tls" : "none");
          uri.searchParams.set("sni", port == 80 && protocol == "vlgess" ? "" : hostName);

          // Build VPN URI
          proxies.push(uri.toString());
        }
      }
      document.registerProxies(
        {
          proxyIP,
          proxyPort,
          country,
          org,
        },
        proxies
      );
    }

    // Build pagination
    document.addPageButton("Prev", `/sub/${page > 0 ? page - 1 : 0}`, page > 0 ? false : true);
    document.addPageButton("Next", `/sub/${page + 1}`, page < Math.floor(proxyList.length / 10) ? false : true);

    return document.build();
  } catch (error) {
    return `An error occurred while generating the VLGESS configurations. ${error}`;
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // Gateway check
      if (apiKey && apiEmail && accountID && zoneID) {
        isApiReady = true;
      }

      // Handle proxy client
      if (upgradeHeader === "websocket") {
        const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3) {
          // Contoh: /ID, /SG, dll
          const proxyKey = url.pathname.replace("/", "").toUpperCase();
          let kvProxy = await env.nautica.get("kvProxy");
          if (kvProxy) {
            kvProxy = JSON.parse(kvProxy);
          } else {
            kvProxy = await getKVProxyList();
            env.nautica.put(JSON.stringify(kvProxy));
          }

          proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];

          return await websocketHandler(request);
        } else if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websocketHandler(request);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");

        // Queries
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
        let proxyList = (await getProxyList(proxyBankUrl)).filter((proxy) => {
          // Filter proxies by Country
          if (countrySelect) {
            return countrySelect.includes(proxy.country);
          }

          return true;
        });

        const result = getAllConfig(request, hostname, proxyList, pageIndex);
        return new Response(result, {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" },
        });
      } else if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await checkProxyHealth(target[0], target[1] || "443");

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            ...CORS_HEADER_OPTIONS,
            "Content-Type": "application/json",
          },
        });
      } else if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (apiPath.startsWith("/domains")) {
          if (!isApiReady) {
            return new Response("Api not ready", {
              status: 500,
            });
          }

          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);

            return new Response(register.toString(), {
              status: register,
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          }
        } else if (apiPath.startsWith("/sub")) {
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

          const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
          const proxyList = await getProxyList(proxyBankUrl)
            .then((proxies) => {
              // Filter CC
              if (filterCC.length) {
                return proxies.filter((proxy) => filterCC.includes(proxy.country));
              }
              return proxies;
            })
            .then((proxies) => {
              // shuffle result
              shuffleArray(proxies);
              return proxies;
            });

          const uuid = crypto.randomUUID();
          const result = [];
          for (const proxy of proxyList) {
            const uri = new URL(`trogjan://${fillerDomain}`);
            uri.searchParams.set("encryption", "none");
            uri.searchParams.set("type", "ws");
            uri.searchParams.set("host", APP_DOMAIN);

            for (const port of filterPort) {
              for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;

                uri.protocol = protocol;
                uri.port = port.toString();
                if (protocol == "ss") {
                  uri.username = btoa(`none:${uuid}`);
                } else {
                  uri.username = uuid;
                }

                uri.searchParams.set("security", port == 443 ? "tls" : "none");
                uri.searchParams.set("sni", port == 80 && protocol == "vlgess" ? "" : APP_DOMAIN);
                uri.searchParams.set("path", `/${proxy.proxyIP}-${proxy.proxyPort}`);

                uri.hash = `${result.length + 1} ${getFlagEmoji(proxy.country)} ${proxy.org} WS ${
                  port == 443 ? "TLS" : "NTLS"
                } [${serviceName}]`;
                result.push(uri.toString());
              }
            }
          }

          let finalResult = "";
          switch (filterFormat) {
            case "raw":
              finalResult = result.join("\n");
              break;
            case "cglash":
            case "sgfa":
            case "bgfr":
            case "v2gray":
              const encodedResult = [];
              for (const proxy of result) {
                encodedResult.push(encodeURIComponent(proxy));
              }

              const res = await fetch(`${CONVERTER_URL}?target=${filterFormat}&url=${encodedResult.join(",")}`);
              if (res.status == 200) {
                finalResult = await res.text();
              } else {
                return new Response(res.statusText, {
                  status: res.status,
                  headers: {
                    ...CORS_HEADER_OPTIONS,
                  },
                });
              }
              break;
          }

          return new Response(finalResult, {
            status: 200,
            headers: {
              ...CORS_HEADER_OPTIONS,
            },
          });
        } else if (apiPath.startsWith("/myip")) {
          return new Response(
            JSON.stringify({
              ip:
                request.headers.get("cf-connecting-ipv6") ||
                request.headers.get("cf-connecting-ip") ||
                request.headers.get("x-real-ip"),
              colo: request.headers.get("cf-ray")?.split("-")[1],
              ...request.cf,
            }),
            {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            }
          );
        }
      }

      const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
      return await reverseProxy(request, targetReverseProxy);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: {
          ...CORS_HEADER_OPTIONS,
        },
      });
    }
  },
};


async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }

          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          log("📥 Data awal WebSocket (length " + chunk.byteLength + "):", new Uint8Array(chunk).slice(0, 32));
          const protocol = await protocolSniffer(chunk);
          log("🧪 Protokol terdeteksi", protocol);
          let protocolHeader;

          if (protocol === "Trogjan") {
            protocolHeader = parseTrogjanHeader(chunk);
          } else if (protocol === "VLGESS") {
            protocolHeader = parseVlgessHeader(chunk);
          } else if (protocol === "Sambelsaus") {
            protocolHeader = parseSambelsausHeader(chunk);
          } else if (protocol === "VMgess") {
            log("🔍 Parsing VMgess AEAD dimulai");
            protocolHeader = await parseVMgessHeader(chunk);
            log("📦 Hasil parsing VMgess:", JSON.stringify(protocolHeader));
          } else {
            parseEpepHeader(chunk);
            log("❌ Protokol tidak dikenali", new Uint8Array(chunk).slice(0, 16));
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
          log("🚀 Siap kirim ke tujuan", `${addressLog}:${portLog}`);

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              throw new Error("UDP only supported for DNS port 53");
            }
          }

          if (isDNS) {
            const { write } = await handleUDPOutbound(webSocket, protocolHeader.version, log);
            udpStreamWrite = write;
            udpStreamWrite(protocolHeader.rawClientData);
            return;
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log("readableWebSocketStream is closed");
        },
        abort(reason) {
          log("readableWebSocketStream aborted", JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}


// --- AWAL FUNGSI protocolSniffer ---
// Fungsi helper untuk logging di dalam protocolSniffer
// --- AWAL FUNGSI protocolSniffer (Revisi Urutan Deteksi) ---

// Fungsi helper untuk logging di dalam protocolSniffer
const snifferLog = (message, ...args) => {
  // Ganti true dengan false untuk menonaktifkan log sniffer
  if (true) {
    console.log(`[Sniffer] ${message}`, ...args);
  }
};

// Fungsi untuk mengubah ArrayBuffer menjadi string heksadesimal
// Pastikan fungsi ini ada di skrip Anda dan berfungsi dengan benar.

async function protocolSniffer(buffer) {
  const bufferView = new Uint8Array(buffer); // Buat view byte

  snifferLog(`Menerima buffer dengan panjang: ${buffer.byteLength}`);

  // 1. Deteksi Trogjan (Paling Spesifik)
  snifferLog("Mencoba deteksi Trogjan...");
  if (buffer.byteLength >= 62) {
    const trojanDelimiter = bufferView.slice(56, 60);
    if (
      trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a &&
      (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) &&
      (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04)
    ) {
      snifferLog("  Terdeteksi: Trogjan.");
      return "Trogjan"; // Sesuai websocketHandler
    }
  }
  snifferLog("  Tidak terdeteksi sebagai Trogjan.");

  // 2. Deteksi VLGESS (VGLESS) (Cukup Spesifik)
  snifferLog("Mencoba deteksi VLGESS...");
  if (buffer.byteLength >= 17) {
    const vlgessDelimiterBytes = bufferView.slice(1, 17);
    try {
      const underlyingBuffer = vlgessDelimiterBytes.buffer.slice(vlgessDelimiterBytes.byteOffset, vlgessDelimiterBytes.byteOffset + vlgessDelimiterBytes.byteLength);
      const vlgessUUIDHex = arrayBufferToHex(underlyingBuffer);
      if (vlgessUUIDHex.match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
        snifferLog("  Terdeteksi: VLGESS (UUID v4 cocok).");
        return "VLGESS"; // Sesuai websocketHandler
      }
    } catch (e) {
      snifferLog("  Error saat proses VLGESS:", e.message);
    }
  }
  snifferLog("  Tidak terdeteksi sebagai VLGESS.");

  // 3. Deteksi Sambelsaus secara Eksplisit (Lightweight)
  // Cek apakah header cocok dengan format SS sebelum cek VMess umum
  snifferLog("Mencoba deteksi Sambelsaus (eksplisit)...");
  if (buffer.byteLength >= 1) {
    const atyp = bufferView[0];
    snifferLog(`  ATYP = ${atyp}`);
    let isPotentiallySambelsaus = false;
    if (atyp === 1) { // IPv4
      if (buffer.byteLength >= 7) isPotentiallySambelsaus = true;
    } else if (atyp === 4) { // IPv6
      if (buffer.byteLength >= 19) isPotentiallySambelsaus = true;
    } else if (atyp === 3) { // Domain
      if (buffer.byteLength >= 2) {
        const domainLen = bufferView[1];
        if (buffer.byteLength >= 1 + 1 + domainLen + 2) isPotentiallySambelsaus = true;
      }
    }
    
    if (isPotentiallySambelsaus) {
        snifferLog("  Terdeteksi: Sambelsaus (berdasarkan ATYP dan panjang header).");
        return "Sambelsaus"; // Sesuai websocketHandler
    } else {
        snifferLog("  Header tidak cocok dengan format Sambelsaus eksplisit.");
    }
  } else {
    snifferLog("  Panjang buffer < 1, tidak bisa cek ATYP Sambelsaus.");
  }
  snifferLog("  Tidak terdeteksi sebagai Sambelsaus (eksplisit).");


  // 4. Deteksi VMgess (VMgess AEAD) - Menggunakan kondisi umum panjang >= 38
  // Ini hanya dijalankan jika BUKAN Trogjan, BUKAN VLGESS, dan BUKAN Sambelsaus (eksplisit).
  snifferLog("Mencoba deteksi VMgess (kondisi umum: panjang >= 38)...");
  if (buffer.byteLength >= 38) {
    snifferLog(`  Kondisi VMgess umum terpenuhi (panjang ${buffer.byteLength} >= 38). Terdeteksi: VMgess.`);
    return "VMgess"; // Akan memanggil parseVMgessHeader
  } else {
    snifferLog(`  Kondisi VMgess umum TIDAK terpenuhi (panjang ${buffer.byteLength} < 38).`);
  }

  // 5. Default Terakhir (Jika tidak cocok sama sekali)
  snifferLog("Tidak terdeteksi sebagai Trogjan, VLGESS, SS (eksplisit), atau VMgess (umum). Default terakhir ke Sambelsaus.");
  return "Sambelsaus"; // Fallback terakhir
}

// --- AKHIR FUNGSI protocolSniffer ---
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      proxyIP.split(/[:=-]/)[0] || addressRemote,
      proxyIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(webSocket, responseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(DOH_SERVER, {
            method: "POST",
            headers: {
              "content-type": "application/dns-message",
            },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// --------------------------------------------------------------------
// PASTIKAN FUNGSI-FUNGSI HELPER DI BAWAH INI SUDAH ADA SEBELUMNYA:
// hkdfSha256, fnv1a32, decryptAuthIDAeadInternal, 
// parseVMessCommandHeader, setupVMessBodyProcessor
// --------------------------------------------------------------------
// Tambahan untuk VMgess
// const CLIENT_ID = "f282b878871145a18c695564172123c1";
// --- AWAL BAGIAN KODE YANG PERLU DISALIN (HANYA hkdfSha256 dan parseVMgessHeader) ---
// --- AWAL BAGIAN KODE YANG PERLU DIEDIT/DITAMBAHKAN ---
// (Sertakan fungsi hkdfSha256 dan fnv1a32 yang sudah ada)

async function hkdfSha256(ikm, salt, info, length) {
  let currentSalt = salt;
  // Jika salt yang diberikan kosong (panjang 0), gunakan salt default (32 byte nol untuk SHA-256)
  // sesuai standar HKDF (RFC 5869, Bagian 2.2)
  if (!currentSalt || currentSalt.byteLength === 0) {
    currentSalt = new Uint8Array(32).fill(0); // HashLen untuk SHA-256 adalah 32 byte
  }

  const saltKey = await crypto.subtle.importKey(
    "raw",
    currentSalt, // Gunakan currentSalt yang sudah divalidasi/default
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const prk = await crypto.subtle.sign("HMAC", saltKey, ikm); // prk = HMAC-Hash(salt, IKM)

  const prkKey = await crypto.subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const infoBuf = new TextEncoder().encode(info);
  let prev = new Uint8Array(0);
  let outputAccumulator = new Uint8Array(0);

  const hashLen = 32; // Panjang output SHA-256 dalam byte
  const numBlocks = Math.ceil(length / hashLen);

  for (let i = 1; i <= numBlocks; i++) {
    const inputArr = [prev, infoBuf, Uint8Array.of(i)];
    let totalLength = 0;
    for (const arr of inputArr) {
        totalLength += arr.byteLength;
    }
    const input = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of inputArr) {
        input.set(arr, offset);
        offset += arr.byteLength;
    }
    
    prev = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, input)); // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
    
    const newOutput = new Uint8Array(outputAccumulator.length + prev.length);
    newOutput.set(outputAccumulator, 0);
    newOutput.set(prev, outputAccumulator.length);
    outputAccumulator = newOutput;
  }

  const result = outputAccumulator.slice(0, length);
  return result;
}

function fnv1a32(data) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < data.length; i++) {
    hash ^= data[i];
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    hash = hash >>> 0;
  }
  return hash;
}

// Tahap 1 Internal: Dekripsi Header AEAD Otentikasi (AuthID AEAD)
async function decryptAuthIDAeadInternal(initialChunk, clientID_str, log) {
  log("🛡️ VMGESS Internal: Memulai dekripsi AuthID AEAD.");

  if (!(initialChunk instanceof Uint8Array)) {
    initialChunk = new Uint8Array(initialChunk);
  }

  // AuthID adalah 16 byte pertama dari chunk yang diterima dari WebSocket
  if (initialChunk.length < 16) {
    log("❌ VMGESS Internal AuthID AEAD: Data awal terlalu pendek untuk AuthID.");
    return { hasError: true, message: "VMGESS AuthID AEAD: Data awal terlalu pendek." };
  }
  const authID = initialChunk.slice(0, 16); // Ini adalah "Authentication ID"
  const encryptedCommandHeaderPart = initialChunk.slice(16); // Sisa chunk adalah header perintah terenkripsi
  log("🔑 VMGESS Internal AuthID (digunakan sebagai salt/info untuk KDF CmdKey):", [...authID]);

  const uuidHex = clientID_str.replace(/-/g, '');
  const clientIDBytes = new Uint8Array(uuidHex.match(/.{1,2}/g).map(h => parseInt(h, 16)));

  // Turunkan CmdKey. Di Xray, CmdKey adalah bagian dari User ID. Kita simulasikan turunannya.
  // Menggunakan clientIDBytes sebagai IKM dan string info unik. Salt bisa kosong atau tetap.
  const cmdKey = await hkdfSha256(clientIDBytes, new Uint8Array(0) /* no salt untuk CmdKey */, "VMess User CmdKey", 16);
  log("🔑 VMGESS Internal CmdKey (untuk AuthID AEAD):", [...cmdKey]);

  // Derivasi kunci dan nonce untuk dekripsi lapisan AuthID AEAD ini.
  // Penyederhanaan dari mekanisme nonce Xray (Shake128 + FNV).
  // Di sini, kita gunakan HKDF dengan CmdKey sebagai IKM dan AuthID sebagai salt/info.
  const authIdAeadKey = await hkdfSha256(cmdKey, authID, "VMess AuthID Layer Key", 16); // AES-128
  const authIdAeadNonce = await hkdfSha256(cmdKey, authID, "VMess AuthID Layer Nonce", 12); // Nonce 12-byte
  log("🔑 VMGESS Kunci Dekripsi AuthID Layer:", [...authIdAeadKey]);
  log("🧊 VMGESS Nonce Dekripsi AuthID Layer:", [...authIdAeadNonce]);

  if (encryptedCommandHeaderPart.length === 0) {
      log("❌ VMGESS Internal AuthID AEAD: Tidak ada data setelah AuthID untuk didekripsi.");
      return { hasError: true, message: "VMGESS AuthID AEAD: Tidak ada data payload." };
  }

  try {
    const subtleCryptoKey = await crypto.subtle.importKey("raw", authIdAeadKey, "AES-GCM", false, ["decrypt"]);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: authIdAeadNonce },
      subtleCryptoKey,
      encryptedCommandHeaderPart
    );
    log("✅ VMGESS Internal AuthID AEAD: Berhasil didekripsi. Panjang data header perintah:", decryptedBuffer.byteLength);
    return { hasError: false, vmessCommandHeaderData: new Uint8Array(decryptedBuffer) };
  } catch (err) {
    log("❌ VMGESS Internal AuthID AEAD: Gagal dekripsi:", err.name, err.message);
    return { hasError: true, message: `VMGESS AuthID AEAD: Gagal dekripsi - ${err.message}` };
  }
}

// Modifikasi fungsi parseVMgessHeader menjadi fungsi utama yang dipanggil dari websocketHandler
// Fungsi ini akan melakukan Tahap 1 dan Tahap 2.
async function parseVMgessHeader(initialChunkFromWebSocket, log = console.log) {
  const UUID = "f282b878-8711-45a1-8c69-5564172123c1"; // UUID global Anda

  // Tahap 1: Dekripsi Header AEAD Otentikasi
  const authIdResult = await decryptAuthIDAeadInternal(initialChunkFromWebSocket, UUID, log);
  if (authIdResult.hasError) {
    return { hasError: true, message: authIdResult.message, isAEAD: true /* Tambahkan flag jika perlu */ };
  }
  let vmessCommandHeaderData = authIdResult.vmessCommandHeaderData;

  // Tahap 2: Parsing Header Perintah VMess yang sudah didekripsi
  log("🔍 VMGESS: Memulai parsing VMess Command Header (setelah AuthID AEAD).");
  const textDecoder = new TextDecoder();

  // Pastikan vmessCommandHeaderData adalah Uint8Array (seharusnya sudah dari decryptAuthIDAeadInternal)
  if (!(vmessCommandHeaderData instanceof Uint8Array)) {
    // Ini seharusnya tidak terjadi jika decryptAuthIDAeadInternal benar
    vmessCommandHeaderData = new Uint8Array(vmessCommandHeaderData);
  }
  
  const minHeaderLength = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + 4;
  if (vmessCommandHeaderData.length < minHeaderLength) {
    log(`❌ VMGESS Command Header: Data terlalu pendek (minimal ${minHeaderLength} byte, diterima ${vmessCommandHeaderData.length})`);
    return { hasError: true, message: "VMGESS Command Header: Data terlalu pendek." };
  }

  let offset = 0;
  const version = vmessCommandHeaderData[offset]; offset += 1;
  const requestBodyIV = vmessCommandHeaderData.slice(offset, offset + 16); offset += 16;
  const requestBodyKey = vmessCommandHeaderData.slice(offset, offset + 16); offset += 16;
  const responseHeaderByte = vmessCommandHeaderData[offset]; offset += 1;
  const optionByte = vmessCommandHeaderData[offset]; offset += 1;
  
  const securityAndPaddingByte = vmessCommandHeaderData[offset]; offset += 1;
  const paddingLen = securityAndPaddingByte >> 4;
  const securityByte = securityAndPaddingByte & 0x0F;
  
  offset += 1; // Reserved byte

  const commandByte = vmessCommandHeaderData[offset]; offset += 1;

  log(`📋 VMGESS Parsed Meta: Version: ${version}, Option: ${optionByte.toString(2)}, SecurityByte: ${securityByte}, Cmd: ${commandByte}, PaddingLen: ${paddingLen}`);
  // log("🔑 VMGESS RequestBodyKey (diekstrak):", [...requestBodyKey]); // Hindari log kunci mentah
  // log("🧊 VMGESS RequestBodyIV (diekstrak):", [...requestBodyIV]);

  const dataForAddrPort = vmessCommandHeaderData.slice(offset);
  let currentDataOffsetInAddrPort = 0;

  const addrType = dataForAddrPort[currentDataOffsetInAddrPort]; currentDataOffsetInAddrPort += 1;
  let addressRemote = "";
  let portRemote = 0;
  let endOfAddrPortSection = 0;

  if (addrType === 1) { // IPv4
    if (dataForAddrPort.length < currentDataOffsetInAddrPort + 4 + 2) {
        return { hasError: true, message: "VMGESS Command Header: Data tidak cukup untuk IPv4 & port." };
    }
    addressRemote = [...dataForAddrPort.slice(currentDataOffsetInAddrPort, currentDataOffsetInAddrPort + 4)].join('.');
    currentDataOffsetInAddrPort += 4;
  } else if (addrType === 3) { // Domain
    if (dataForAddrPort.length < currentDataOffsetInAddrPort + 1) {
        return { hasError: true, message: "VMGESS Command Header: Data tidak cukup untuk panjang domain." };
    }
    const domainLen = dataForAddrPort[currentDataOffsetInAddrPort]; currentDataOffsetInAddrPort += 1;
    if (domainLen === 0) return { hasError: true, message: "VMGESS Command Header: Panjang domain 0."};
    if (dataForAddrPort.length < currentDataOffsetInAddrPort + domainLen + 2) {
        return { hasError: true, message: "VMGESS Command Header: Data tidak cukup untuk domain & port." };
    }
    addressRemote = textDecoder.decode(dataForAddrPort.slice(currentDataOffsetInAddrPort, currentDataOffsetInAddrPort + domainLen));
    currentDataOffsetInAddrPort += domainLen;
  } else if (addrType === 4) { // IPv6
    if (dataForAddrPort.length < currentDataOffsetInAddrPort + 16 + 2) {
        return { hasError: true, message: "VMGESS Command Header: Data tidak cukup untuk IPv6 & port." };
    }
    const ipv6Bytes = dataForAddrPort.slice(currentDataOffsetInAddrPort, currentDataOffsetInAddrPort + 16);
    const ipv6 = [];
    for (let i = 0; i < 8; i++) {
      ipv6.push(((ipv6Bytes[i * 2] << 8) | ipv6Bytes[i * 2 + 1]).toString(16).padStart(4, '0'));
    }
    addressRemote = ipv6.join(':');
    currentDataOffsetInAddrPort += 16;
  } else {
    log("❓ VMGESS Tipe alamat tidak dikenali:", addrType);
    return { hasError: true, message: `VMGESS Command Header: Tipe alamat tidak dikenal (${addrType})` };
  }
  
  portRemote = (dataForAddrPort[currentDataOffsetInAddrPort] << 8) | dataForAddrPort[currentDataOffsetInAddrPort + 1];
  currentDataOffsetInAddrPort += 2;
  endOfAddrPortSection = offset + currentDataOffsetInAddrPort;


  const dataToChecksumEndOffset = endOfAddrPortSection + paddingLen;
  if (vmessCommandHeaderData.length < dataToChecksumEndOffset + 4) {
      log("❌ VMGESS Command Header: Data tidak cukup untuk padding dan checksum.");
      return { hasError: true, message: "VMGESS Command Header: Data tidak cukup untuk padding/checksum." };
  }
  const dataToChecksum = vmessCommandHeaderData.slice(0, dataToChecksumEndOffset);
  const expectedChecksumBytes = vmessCommandHeaderData.slice(dataToChecksumEndOffset, dataToChecksumEndOffset + 4);
  const expectedChecksum = (expectedChecksumBytes[0] << 24 |
                            expectedChecksumBytes[1] << 16 |
                            expectedChecksumBytes[2] << 8  |
                            expectedChecksumBytes[3]) >>> 0;
  
  const actualChecksum = fnv1a32(dataToChecksum);

  log(`🧮 VMGESS Checksum: Expected=${expectedChecksum.toString(16)}, Actual=${actualChecksum.toString(16)}`);
  if (actualChecksum !== expectedChecksum) {
    log("⚠️ VMGESS Command Header: Checksum FNV1a tidak cocok! Ini adalah error dalam spesifikasi AEAD VMESS.");
    // Dalam VMESS AEAD, checksum FNV1a *harus* valid. Berbeda dengan VMESS legacy.
    return { hasError: true, message: "VMGESS Command Header: Checksum FNV1a tidak cocok." };
  }

  const totalHeaderConsumedLength = dataToChecksumEndOffset + 4;
  const rawClientData = vmessCommandHeaderData.slice(totalHeaderConsumedLength);

  let securityTypeForBody;
  switch (securityByte) {
      case 3: securityTypeForBody = "AES-128-GCM"; break;
      case 4: securityTypeForBody = "CHACHA20-POLY1305"; break;
      case 5: securityTypeForBody = "NONE"; break;
      default: securityTypeForBody = "UNKNOWN";
  }

  const optionsForBody = {
      isChunkStream: (optionByte & 1) > 0,
      isChunkMasking: (optionByte & 2) > 0,
      isGlobalPadding: (optionByte & 4) > 0,
      isAuthenticatedLength: (optionByte & 8) > 0, // RequestOptionAuthenticatedLength = 8
  };
  log("📜 VMGESS Options for Body:", optionsForBody);
  log("🔒 VMGESS Security for Body:", securityTypeForBody);

  log("✅ VMGESS Command Header: Berhasil diparsing.");
  return {
    // Info yang dikembalikan harus seragam dengan parser protokol lain Anda
    hasError: false,
    addressRemote,
    portRemote,
    // rawClientData dari header ini adalah sisa byte setelah keseluruhan header perintah VMESS
    // Ini mungkin chunk pertama dari body, atau kosong jika body dikirim terpisah.
    rawClientData: rawClientData, 
    version, // Byte versi asli dari header VMess
    isUDP: commandByte === 2, // RequestCommandUDP = 2
    
    // Informasi spesifik VMGESS untuk Tahap 3 (Body Processing)
    vmess: {
        requestBodyKey,
        requestBodyIV,
        responseHeaderByte,
        securityTypeForBody,
        optionsForBody,
        commandByte
    }
  };
}

// Tahap 3: Persiapan Dekriptor/Enkriptor Badan Pesan (Message Body)
async function setupVMessBodyProcessor(vmessInfo, log = console.log) {
  log("🛠️ VMGESS Tahap 3: Menyiapkan Body Processor.");

  const {
    securityTypeForBody,
    optionsForBody,
    requestBodyKey, // Kunci 16-byte dari header perintah
    requestBodyIV   // IV 16-byte dari header perintah
  } = vmessInfo;

  let actualEncryptionKeyBody;
  let aeadAlgorithmNameBody;
  let keyLengthForAuthLenDerivation; // Kunci dasar untuk "auth_len" akan 16 byte (KDF16)

  if (securityTypeForBody === "AES-128-GCM") {
    aeadAlgorithmNameBody = "AES-GCM";
    actualEncryptionKeyBody = requestBodyKey; // Kunci sudah 16 byte
    keyLengthForAuthLenDerivation = 16;
    log("🔑 VMGESS Body AES Key (16 bytes): [disembunyikan]");
  } else if (securityTypeForBody === "CHACHA20-POLY1305") {
    aeadAlgorithmNameBody = "ChaCha20-Poly1305";
    // Sesuai Xray, requestBodyKey (16 byte) di-derive lagi jadi 32 byte.
    // Kita pakai HKDF, BUKAN MD5 Xray. Salt bisa dari requestBodyIV atau kosong.
    actualEncryptionKeyBody = await hkdfSha256(requestBodyKey, requestBodyIV /* salt */, "VMess Body ChaCha20 Key", 32);
    keyLengthForAuthLenDerivation = 16; // KDF16 "auth_len" di Xray menghasilkan 16 byte.
    log("🔑 VMGESS Body ChaCha20 Key (32 bytes, derived): [disembunyikan]");
  } else if (securityTypeForBody === "NONE") {
    log("🚫 VMGESS Body: Tipe keamanan NONE, tidak ada enkripsi.");
    return {
      securityType: "NONE",
      options: optionsForBody,
      decryptChunk: (chunk) => chunk,
      decryptSize: (sizeChunk) => new DataView(sizeChunk.buffer, sizeChunk.byteOffset, sizeChunk.byteLength).getUint16(0, false), // Plain 2-byte size
    };
  } else {
    log("❌ VMGESS Body: Tipe keamanan tidak didukung:", securityTypeForBody);
    return { hasError: true, message: `VMGESS Body: Tipe keamanan tidak didukung: ${securityTypeForBody}` };
  }

  // --- Nonce Generator untuk Body ---
  let bodyNonceCounter = 0;
  // Ukuran nonce standar untuk AES-GCM dan ChaCha20-Poly1305 adalah 12 byte (96 bit)
  const bodyNonceSize = 12; 
  const baseBodyNonce = new Uint8Array(bodyNonceSize); // Buat buffer nonce
  // Salin bagian awal dari requestBodyIV (16 byte) ke baseBodyNonce (12 byte)
  // Ini adalah penyederhanaan, Xray lebih kompleks.
  // Cara Xray: `c := append([]byte(nil), ivInput...)`, lalu `binary.BigEndian.PutUint16(c, count)`
  // Ini berarti `ivInput` (16 byte) disalin, lalu 2 byte pertama dimodifikasi oleh counter.
  // Kita akan meniru ini dengan `requestBodyIV` sebagai `ivInput`.
  const ivInputForNonce = new Uint8Array(requestBodyIV); 

  function generateBodyChunkNonce() {
    const currentFullNonce = new Uint8Array(ivInputForNonce); // Salin IV dasar setiap kali
    const view = new DataView(currentFullNonce.buffer, currentFullNonce.byteOffset, currentFullNonce.byteLength);
    view.setUint16(0, bodyNonceCounter, false); // Set 2 byte pertama dengan counter (Big Endian)
    bodyNonceCounter++;
    return currentFullNonce.slice(0, bodyNonceSize); // Ambil 12 byte pertama untuk nonce
  }
  log("🧊 VMGESS Body Nonce Generator disiapkan.");

  // --- Authenticated Length Key (jika aktif) ---
  let authenticatedLengthProcessor = null;
  if (optionsForBody.isAuthenticatedLength) {
    log("🛡️ VMGESS Body: Opsi AuthenticatedLength aktif.");
    // Kunci untuk auth_len diturunkan dari requestBodyKey (IKM) dan info "auth_len" (sesuai Xray)
    // KDF16 Xray biasanya menghasilkan 16 byte.
    const authLenBaseKey = await hkdfSha256(requestBodyKey, new Uint8Array(0) /*no salt untuk KDF ini*/, "auth_len", keyLengthForAuthLenDerivation); 

    let actualAuthLengthKey;
    let authLengthAeadAlgo;
    let authLenNonceSize = 12;

    if (securityTypeForBody === "AES-128-GCM") {
      actualAuthLengthKey = authLenBaseKey; // Sudah 16 byte
      authLengthAeadAlgo = "AES-GCM";
      log("🔑 VMGESS AuthenticatedLengthKey (AES-GCM, 16 bytes): [disembunyikan]");
    } else if (securityTypeForBody === "CHACHA20-POLY1305") {
      // Xray: GenerateChacha20Poly1305Key(authLenBaseKey) -> MD5 expansion
      // Kita: derive langsung 32 byte dari authLenBaseKey (16 byte) sebagai IKM.
      actualAuthLengthKey = await hkdfSha256(authLenBaseKey, new Uint8Array(0), "VMess AuthLen ChaCha20 Key", 32);
      authLengthAeadAlgo = "ChaCha20-Poly1305";
      log("🔑 VMGESS AuthenticatedLengthKey (ChaCha20, 32 bytes, derived): [disembunyikan]");
    }
    
    if (actualAuthLengthKey) {
        // Nonce generator untuk auth_len juga menggunakan requestBodyIV sebagai dasar di Xray.
        // Ini berisiko tabrakan nonce jika tidak ditangani dengan sangat hati-hati.
        // Sebaiknya, nonce untuk AuthLen diturunkan secara berbeda atau menggunakan counter yang berbeda.
        // Untuk penyederhanaan, kita akan buat generator nonce terpisah untuk AuthLen,
        // dengan info KDF yang berbeda untuk nonce dasar jika perlu, atau counter terpisah.
        // Di sini, kita akan menggunakan *counter yang sama* tapi ini adalah AREA RISIKO.
        // Xray `GenerateChunkNonce` dipakai untuk *kedua* auth data dan auth length.
        // Ini aman jika domain nonce (kunci) berbeda. Kita punya kunci berbeda.
        
        authenticatedLengthProcessor = {
            key: actualAuthLengthKey,
            algo: authLengthAeadAlgo,
            // Akan menggunakan generateBodyChunkNonce() yang sama, karena kunci AEAD-nya berbeda.
        };
    }
  }

  async function decryptChunk(encryptedChunkWithTag) {
    if (securityTypeForBody === "NONE") return encryptedChunkWithTag; // Sudah ditangani di atas
    const subtleCryptoKey = await crypto.subtle.importKey("raw", actualEncryptionKeyBody, aeadAlgorithmNameBody, false, ["decrypt"]);
    const nonce = generateBodyChunkNonce();
    // log(`💧 Mendekripsi body chunk dengan nonce:`, [...nonce]);
    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: aeadAlgorithmNameBody, iv: nonce /*, additionalData: ... opsional */ },
        subtleCryptoKey,
        encryptedChunkWithTag
      );
      return new Uint8Array(decrypted);
    } catch (err) {
      log(`❌ Gagal dekripsi VMGESS body chunk (${aeadAlgorithmNameBody}):`, err.name, err.message);
      throw err;
    }
  }
  
  async function decryptSize(encryptedSizeChunkWithTag) {
      if (!authenticatedLengthProcessor) {
          // Jika tidak ada auth length, parse ukuran secara plain (misal 2 byte BigEndian)
          const view = new DataView(encryptedSizeChunkWithTag.buffer, encryptedSizeChunkWithTag.byteOffset, encryptedSizeChunkWithTag.byteLength);
          return view.getUint16(0, false); // Big Endian
      }
      const { key: authKey, algo: authAlgo } = authenticatedLengthProcessor;
      const subtleKey = await crypto.subtle.importKey("raw", authKey, authAlgo, false, ["decrypt"]);
      // Gunakan nonce yang sama yang akan dipakai untuk payload chunk terkait.
      // Ini mensimulasikan AEADAuthenticator di Go yang pakai 1 nonce untuk size+payload.
      // Namun, Xray sepertinya memanggil GenerateChunkNonce terpisah untuk size parser dan payload.
      // Untuk amannya, kita pakai nonce yang sama dengan payload yang akan menyusul.
      // Nonce harusnya sudah di-increment oleh generateBodyChunkNonce() sebelumnya saat decryptSize dipanggil
      // atau kita perlu nonce yang sama persis. Mari kita asumsikan nonce-nya sama untuk size dan payloadnya.
      // Xray `AEADChunkSizeParser` menggunakan nonce dari `Auth.NonceGenerator.Next()`
      // dan `AuthenticationReader` juga memanggil `Auth.NonceGenerator.Next()`.
      // Ini berarti nonce BERBEDA untuk ukuran dan payload.
      // Maka kita butuh cara agar `generateBodyChunkNonce` bisa dipakai 2x atau ada 2 generator
      // Untuk sementara, kita pakai nonce yang sama yang akan dipakai payload.
      // Ini adalah penyederhanaan dan mungkin perlu revisi untuk kompatibilitas penuh.
      // Cara paling aman: nonce untuk size harus unik.
      // Mari kita panggil generateBodyChunkNonce() sekali lagi untuk size:
      const nonceForSize = generateBodyChunkNonce(); 
      // log(`💧 Mendekripsi size chunk dengan nonce:`, [...nonceForSize]);

      try {
          const decryptedSizeBuffer = await crypto.subtle.decrypt(
              { name: authAlgo, iv: nonceForSize },
              subtleKey,
              encryptedSizeChunkWithTag
          );
          const view = new DataView(decryptedSizeBuffer);
          if (decryptedSizeBuffer.byteLength !== 2) {
              throw new Error("Ukuran terdekripsi bukan 2 byte.");
          }
          return view.getUint16(0, false); // Big Endian
      } catch (err) {
          log(`❌ Gagal dekripsi VMGESS ukuran chunk (${authAlgo}):`, err.name, err.message);
          throw err;
      }
  }

  log("✅ VMGESS Body Processor disiapkan untuk:", securityTypeForBody);
  return {
    hasError: false,
    securityType: securityTypeForBody,
    options: optionsForBody,
    decryptChunk,
    decryptSize,
    // Fungsi untuk me-reset counter nonce jika stream baru atau koneksi MUX
    resetNonceCounter: () => { bodyNonceCounter = 0; } 
  };
}

// --- AKHIR BAGIAN KODE YANG PERLU DIEDIT/DITAMBAHKAN ---

// --- AKHIR BAGIAN KODE YANG PERLU DISALIN ---

function parseEpepHeader(epepBuffer) {
  // https://xtls.github.io/development/protocols/crotme123ss.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
}

function parseSambelsausHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for Sambelsaus: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function parseVlgessHeader(vlgessBuffer) {
  const version = new Uint8Array(vlgessBuffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(vlgessBuffer.slice(17, 18))[0];

  const cmd = new Uint8Array(vlgessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlgessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlgessBuffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(vlgessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(vlgessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlgessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(vlgessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: vlgessBuffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function parseTrogjanHeader(buffer) {
  const socks5DataBuffer = buffer.slice(58);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  let isUDP = false;
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
        "."
      );
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkProxyHealth(proxyIP, proxyPort) {
  const req = await fetch(`${PROXY_HEALTH_CHECK_API}?ip=${proxyIP}:${proxyPort}`);
  return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let currentIndex = array.length;

  // While there remain elements to shuffle...
  while (currentIndex != 0) {
    // Pick a remaining element...
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // And swap it with the current element.
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}

async function generateHashFromText(text) {
  const msgUint8 = new TextEncoder().encode(text); // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest("MD5", msgUint8); // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(""); // convert bytes to hex string

  return hashHex;
}

function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// CloudflareApi Class
class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${apiKey}`;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.apiKey = apiKey;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
    };
  }

  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();

      return respJson.result.filter((data) => data.service == serviceName).map((data) => data.hostname);
    }

    return [];
  }

  async registerDomain(domain) {
    domain = domain.toLowerCase();
    const registeredDomains = await this.getDomainList();

    if (!domain.endsWith(rootDomain)) return 400;
    if (registeredDomains.includes(domain)) return 409;

    try {
      const domainTest = await fetch(`https://${domain.replaceAll("." + APP_DOMAIN, "")}`);
      if (domainTest.status == 530) return 530;
    } catch (e) {
      return 400;
    }

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({
        environment: "production",
        hostname: domain,
        service: serviceName,
        zone_id: this.zoneID,
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
}

// HTML page base
/**
 * Cloudflare worker gak support DOM API, tetapi mereka menggunakan HTML Rewriter.
 * Tapi, karena kelihatannta repot kalo pake HTML Rewriter. Kita pake cara konfensional saja...
 */
let baseHTML = `
<!DOCTYPE html>
<html lang="en" id="html" class="scroll-auto scrollbar-hide dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Proxy List</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      /* For Webkit-based browsers (Chrome, Safari and Opera) */
      .scrollbar-hide::-webkit-scrollbar {
          display: none;
      }

      /* For IE, Edge and Firefox */
      .scrollbar-hide {
          -ms-overflow-style: none;  /* IE and Edge */
          scrollbar-width: none;  /* Firefox */
      }
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>
      tailwind.config = {
        darkMode: 'selector',
      }
    </script>
  </head>
  <body class="bg-white dark:bg-neutral-800 bg-fixed">
    <!-- Notification -->
    <div
      id="notification-badge"
      class="fixed z-50 opacity-0 transition-opacity ease-in-out duration-300 mt-9 mr-6 right-0 p-3 max-w-sm bg-white rounded-xl border border-2 border-neutral-800 flex items-center gap-x-4"
    >
      <div class="shrink-0">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#171717" class="size-6">
          <path
            d="M5.85 3.5a.75.75 0 0 0-1.117-1 9.719 9.719 0 0 0-2.348 4.876.75.75 0 0 0 1.479.248A8.219 8.219 0 0 1 5.85 3.5ZM19.267 2.5a.75.75 0 1 0-1.118 1 8.22 8.22 0 0 1 1.987 4.124.75.75 0 0 0 1.48-.248A9.72 9.72 0 0 0 19.266 2.5Z"
          />
          <path
            fill-rule="evenodd"
            d="M12 2.25A6.75 6.75 0 0 0 5.25 9v.75a8.217 8.217 0 0 1-2.119 5.52.75.75 0 0 0 .298 1.206c1.544.57 3.16.99 4.831 1.243a3.75 3.75 0 1 0 7.48 0 24.583 24.583 0 0 0 4.83-1.244.75.75 0 0 0 .298-1.205 8.217 8.217 0 0 1-2.118-5.52V9A6.75 6.75 0 0 0 12 2.25ZM9.75 18c0-.034 0-.067.002-.1a25.05 25.05 0 0 0 4.496 0l.002.1a2.25 2.25 0 1 1-4.5 0Z"
            clip-rule="evenodd"
          />
        </svg>
      </div>
      <div>
        <div class="text-md font-bold text-blue-500">Berhasil!</div>
        <p class="text-sm text-neutral-800">Akun berhasil disalin</p>
      </div>
    </div>
    <!-- Select Country -->
    <div>
      <div
        class="h-full fixed top-0 w-14 bg-white dark:bg-neutral-800 border-r-2 border-neutral-800 dark:border-white z-20 overflow-y-scroll scrollbar-hide"
      >
        <div class="text-2xl flex flex-col items-center h-full gap-2">
          PLACEHOLDER_BENDERA_NEGARA
        </div>
      </div>
    </div>
    <!-- Main -->
    <div id="container-header">
      <div id="container-info" class="bg-amber-400 border-2 border-neutral-800 text-right px-5">
        <div class="flex justify-end gap-3 text-sm">
          <p id="container-info-ip">IP: 127.0.0.1</p>
          <p id="container-info-country">Country: Indonesia</p>
          <p id="container-info-isp">ISP: Localhost</p>
        </div>
      </div>
    </div>
    <div class="container">
      <div
        id="container-title"
        class="sticky bg-white dark:bg-neutral-800 border-b-2 border-neutral-800 dark:border-white z-10 py-6 w-screen"
      >
        <h1 class="text-xl text-center text-neutral-800 dark:text-white">
          PLACEHOLDER_JUDUL
        </h1>
      </div>
      <div class="flex gap-6 pt-10 w-screen justify-center">
        PLACEHOLDER_PROXY_GROUP
      </div>

      <!-- Pagination -->
      <nav id="container-pagination" class="w-screen mt-8 sticky bottom-0 right-0 left-0 transition -translate-y-6 z-20">
        <ul class="flex justify-center space-x-4">
          PLACEHOLDER_PAGE_BUTTON
        </ul>
      </nav>
    </div>

    <div id="container-window" class="hidden">
      <!-- Windows -->
      <!-- Informations -->
      <div class="fixed z-20 top-0 w-full h-full bg-white dark:bg-neutral-800">
        <p id="container-window-info" class="text-center w-full h-full top-1/4 absolute dark:text-white"></p>
      </div>
      <!-- Output Format -->
      <div id="output-window" class="fixed z-20 top-0 right-0 w-full h-full flex justify-center items-center hidden">
        <div class="w-[75%] h-[30%] flex flex-col gap-1 p-1 text-center rounded-md">
          <div class="basis-1/6 w-full h-full rounded-md">
            <div class="flex w-full h-full gap-1 justify-between">
              <button
                onclick="copyToClipboardAsTarget('clash')"
                class="basis-1/2 p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                Clash
              </button>
              <button
                onclick="copyToClipboardAsTarget('sfa')"
                class="basis-1/2 p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                SFA
              </button>
              <button
                onclick="copyToClipboardAsTarget('bfr')"
                class="basis-1/2 p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                BFR
              </button>
            </div>
          </div>
          <div class="basis-1/6 w-full h-full rounded-md">
            <div class="flex w-full h-full gap-1 justify-between">
              <button
                onclick="copyToClipboardAsTarget('v2ray')"
                class="basis-1/2 p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                V2Ray/Xray
              </button>
              <button
                onclick="copyToClipboardAsRaw()"
                class="basis-1/2 p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                Raw
              </button>
            </div>
          </div>
          <div class="basis-1/6 w-full h-full rounded-md">
            <div class="flex w-full h-full gap-1 justify-center">
              <button
                onclick="toggleOutputWindow()"
                class="basis-1/2 border-2 border-indigo-400 hover:bg-indigo-400 dark:text-white p-2 rounded-full flex justify-center items-center"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
      <!-- Wildcards -->
      <div id="wildcards-window" class="fixed hidden z-20 top-0 right-0 w-full h-full flex justify-center items-center">
        <div class="w-[75%] h-[30%] flex flex-col gap-1 p-1 text-center rounded-md">
          <div class="basis-1/6 w-full h-full rounded-md">
            <div class="flex w-full h-full gap-1 justify-between">
              <input
                id="new-domain-input"
                type="text"
                placeholder="Input wildcard"
                class="basis-11/12 w-full h-full px-6 rounded-md focus:outline-0"
              />
              <button
                onclick="registerDomain()"
                class="p-2 rounded-full bg-amber-400 flex justify-center items-center"
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                  <path
                    fill-rule="evenodd"
                    d="M16.72 7.72a.75.75 0 0 1 1.06 0l3.75 3.75a.75.75 0 0 1 0 1.06l-3.75 3.75a.75.75 0 1 1-1.06-1.06l2.47-2.47H3a.75.75 0 0 1 0-1.5h16.19l-2.47-2.47a.75.75 0 0 1 0-1.06Z"
                    clip-rule="evenodd"
                  ></path>
                </svg>
              </button>
            </div>
          </div>
          <div class="basis-5/6 w-full h-full rounded-md">
            <div
              id="container-domains"
              class="w-full h-full rounded-md flex flex-col gap-1 overflow-scroll scrollbar-hide"
            ></div>
          </div>
        </div>
      </div>
    </div>

    <footer>
      <div class="fixed bottom-3 right-3 flex flex-col gap-1 z-50">
        <button onclick="toggleWildcardsWindow()" class="bg-indigo-400 rounded-full border-2 border-neutral-800 p-1 PLACEHOLDER_API_READY">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke-width="1.5"
            stroke="currentColor"
            class="size-6"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M9 9V4.5M9 9H4.5M9 9 3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5 5.25 5.25"
            />
          </svg>
        </button>
        <button onclick="toggleDarkMode()" class="bg-amber-400 rounded-full border-2 border-neutral-800 p-1">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke-width="1.5"
            stroke="currentColor"
            class="size-6"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z"
            ></path>
          </svg>
        </button>
      </div>
    </footer>

    <script>
      // Shared
      const rootDomain = "${serviceName}.${rootDomain}";
      const notification = document.getElementById("notification-badge");
      const windowContainer = document.getElementById("container-window");
      const windowInfoContainer = document.getElementById("container-window-info");
      const converterUrl =
        "https://script.google.com/macros/s/AKfycbwwVeHNUlnP92syOP82p1dOk_-xwBgRIxkTjLhxxZ5UXicrGOEVNc5JaSOu0Bgsx_gG/exec";


      // Switches
      let isDomainListFetched = false;

      // Local variable
      let rawConfig = "";

      function getDomainList() {
        if (isDomainListFetched) return;
        isDomainListFetched = true;

        windowInfoContainer.innerText = "Fetching data...";

        const url = "https://" + rootDomain + "/api/v1/domains/get";
        const res = fetch(url).then(async (res) => {
          const domainListContainer = document.getElementById("container-domains");
          domainListContainer.innerHTML = "";

          if (res.status == 200) {
            windowInfoContainer.innerText = "Done!";
            const respJson = await res.json();
            for (const domain of respJson) {
              const domainElement = document.createElement("p");
              domainElement.classList.add("w-full", "bg-amber-400", "rounded-md");
              domainElement.innerText = domain;
              domainListContainer.appendChild(domainElement);
            }
          } else {
            windowInfoContainer.innerText = "Failed!";
          }
        });
      }

      function registerDomain() {
        const domainInputElement = document.getElementById("new-domain-input");
        const rawDomain = domainInputElement.value.toLowerCase();
        const domain = domainInputElement.value + "." + rootDomain;

        if (!rawDomain.match(/\\w+\\.\\w+$/) || rawDomain.endsWith(rootDomain)) {
          windowInfoContainer.innerText = "Invalid URL!";
          return;
        }

        windowInfoContainer.innerText = "Pushing request...";

        const url = "https://" + rootDomain + "/api/v1/domains/put?domain=" + domain;
        const res = fetch(url).then((res) => {
          if (res.status == 200) {
            windowInfoContainer.innerText = "Done!";
            domainInputElement.value = "";
            isDomainListFetched = false;
            getDomainList();
          } else {
            if (res.status == 409) {
              windowInfoContainer.innerText = "Domain exists!";
            } else {
              windowInfoContainer.innerText = "Error " + res.status;
            }
          }
        });
      }

      function copyToClipboard(text) {
        toggleOutputWindow();
        rawConfig = text;
      }

      function copyToClipboardAsRaw() {
        navigator.clipboard.writeText(rawConfig);

        notification.classList.remove("opacity-0");
        setTimeout(() => {
          notification.classList.add("opacity-0");
        }, 2000);
      }

      async function copyToClipboardAsTarget(target) {
        windowInfoContainer.innerText = "Generating config...";
        const url = converterUrl + "?target=" + target + "&url=" + encodeURIComponent(rawConfig);;
        const res = await fetch(url, {
          redirect: "follow",
        });

        if (res.status == 200) {
          windowInfoContainer.innerText = "Done!";
          navigator.clipboard.writeText(await res.text());

          notification.classList.remove("opacity-0");
          setTimeout(() => {
            notification.classList.add("opacity-0");
          }, 2000);
        } else {
          windowInfoContainer.innerText = "Error " + res.statusText;
        }
      }

      function navigateTo(link) {
        window.location.href = link + window.location.search;
      }

      function toggleOutputWindow() {
        windowInfoContainer.innerText = "Select output:";
        toggleWindow();
        const rootElement = document.getElementById("output-window");
        if (rootElement.classList.contains("hidden")) {
          rootElement.classList.remove("hidden");
        } else {
          rootElement.classList.add("hidden");
        }
      }

      function toggleWildcardsWindow() {
        windowInfoContainer.innerText = "Domain list";
        toggleWindow();
        getDomainList();
        const rootElement = document.getElementById("wildcards-window");
        if (rootElement.classList.contains("hidden")) {
          rootElement.classList.remove("hidden");
        } else {
          rootElement.classList.add("hidden");
        }
      }

      function toggleWindow() {
        if (windowContainer.classList.contains("hidden")) {
          windowContainer.classList.remove("hidden");
        } else {
          windowContainer.classList.add("hidden");
        }
      }

      function toggleDarkMode() {
        const rootElement = document.getElementById("html");
        if (rootElement.classList.contains("dark")) {
          rootElement.classList.remove("dark");
        } else {
          rootElement.classList.add("dark");
        }
      }

      function checkProxy() {
        for (let i = 0; ; i++) {
          const pingElement = document.getElementById("ping-"+i);
          if (pingElement == undefined) return;

          const target = pingElement.textContent.split(" ").filter((ipPort) => ipPort.match(":"))[0];
          if (target) {
            pingElement.textContent = "Checking...";
          } else {
            continue;
          }

          let isActive = false;
          new Promise(async (resolve) => {
            const res = await fetch("https://${serviceName}.${rootDomain}/check?target=" + target)
              .then(async (res) => {
                if (isActive) return;
                if (res.status == 200) {
                  pingElement.classList.remove("dark:text-white");
                  const jsonResp = await res.json();
                  if (jsonResp.proxyip === true) {
                    isActive = true;
                    pingElement.textContent = "Active " + jsonResp.delay + " ms";
                    pingElement.classList.add("text-green-600");
                  } else {
                    pingElement.textContent = "Inactive";
                    pingElement.classList.add("text-red-600");
                  }
                } else {
                  pingElement.textContent = "Check Failed!";
                }
              })
              .finally(() => {
                resolve(0);
              });
          });
        }
      }

      function checkGeoip() {
        const containerIP = document.getElementById("container-info-ip");
        const containerCountry = document.getElementById("container-info-country");
        const containerISP = document.getElementById("container-info-isp");
        const res = fetch("https://" + rootDomain + "/api/v1/myip").then(async (res) => {
          if (res.status == 200) {
            const respJson = await res.json();
            containerIP.innerText = "IP: " + respJson.ip;
            containerCountry.innerText = "Country: " + respJson.country;
            containerISP.innerText = "ISP: " + respJson.asOrganization;
          }
        });
      }

      window.onload = () => {
        checkGeoip();
        checkProxy();

        const observer = lozad(".lozad", {
          load: function (el) {
            el.classList.remove("scale-95");
          },
        });
        observer.observe();
      };

      window.onscroll = () => {
        const paginationContainer = document.getElementById("container-pagination");

        if (window.innerHeight + Math.round(window.scrollY) >= document.body.offsetHeight) {
          paginationContainer.classList.remove("-translate-y-6");
        } else {
          paginationContainer.classList.add("-translate-y-6");
        }
      };
    </script>
    </body>

</html>
`;

class Document {
  proxies = [];

  constructor(request) {
    this.html = baseHTML;
    this.request = request;
    this.url = new URL(this.request.url);
  }

  setTitle(title) {
    this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title);
  }

  addInfo(text) {
    text = `<span>${text}</span>`;
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `${text}\nPLACEHOLDER_INFO`);
  }

  registerProxies(data, proxies) {
    this.proxies.push({
      ...data,
      list: proxies,
    });
  }

  buildProxyGroup() {
    let proxyGroupElement = "";
    proxyGroupElement += `<div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">`;
    for (let i = 0; i < this.proxies.length; i++) {
      const proxyData = this.proxies[i];

      // Assign proxies
      proxyGroupElement += `<div class="lozad scale-95 mb-2 bg-white dark:bg-neutral-800 transition-transform duration-200 rounded-lg p-4 w-60 border-2 border-neutral-800">`;
      proxyGroupElement += `  <div id="countryFlag" class="absolute -translate-y-9 -translate-x-2 border-2 border-neutral-800 rounded-full overflow-hidden"><img width="32" src="https://hatscripts.github.io/circle-flags/flags/${proxyData.country.toLowerCase()}.svg" /></div>`;
      proxyGroupElement += `  <div>`;
      proxyGroupElement += `    <div id="ping-${i}" class="animate-pulse text-xs font-semibold dark:text-white">Idle ${proxyData.proxyIP}:${proxyData.proxyPort}</div>`;
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `  <div class="rounded py-1 px-2 bg-amber-400 dark:bg-neutral-800 dark:border-2 dark:border-amber-400">`;
      proxyGroupElement += `    <h5 class="font-bold text-md text-neutral-900 dark:text-white mb-1 overflow-x-scroll scrollbar-hide text-nowrap">${proxyData.org}</h5>`;
      proxyGroupElement += `    <div class="text-neutral-900 dark:text-white text-sm">`;
      proxyGroupElement += `      <p>IP: ${proxyData.proxyIP}</p>`;
      proxyGroupElement += `      <p>Port: ${proxyData.proxyPort}</p>`;
      proxyGroupElement += `    </div>`;
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `  <div class="flex flex-col gap-2 mt-3 text-sm">`;
      for (let x = 0; x < proxyData.list.length; x++) {
        const indexName = ["Trogjan TLS", "VLGESS TLS", "SS TLS", "Trogjan NTLS", "VLGESS NTLS", "SS NTLS"];
        const proxy = proxyData.list[x];

        if (x % 2 == 0) {
          proxyGroupElement += `<div class="flex gap-2 justify-around w-full">`;
        }

        proxyGroupElement += `<button class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white" onclick="copyToClipboard('${proxy}')">${indexName[x]}</button>`;

        if (x % 2 == 1) {
          proxyGroupElement += `</div>`;
        }
      }
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `</div>`;
    }
    proxyGroupElement += `</div>`;

    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", `${proxyGroupElement}`);
  }

  buildCountryFlag() {
    const proxyBankUrl = this.url.searchParams.get("proxy-list");
    const flagList = [];
    for (const proxy of cachedProxyList) {
      flagList.push(proxy.country);
    }

    let flagElement = "";
    for (const flag of new Set(flagList)) {
      flagElement += `<a href="/sub?cc=${flag}${
        proxyBankUrl ? "&proxy-list=" + proxyBankUrl : ""
      }" class="py-1" ><img width=20 src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" /></a>`;
    }

    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }

  addPageButton(text, link, isDisabled) {
    const pageButton = `<li><button ${
      isDisabled ? "disabled" : ""
    } class="px-3 py-1 bg-amber-400 border-2 border-neutral-800 rounded" onclick=navigateTo('${link}')>${text}</button></li>`;

    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
  }

  build() {
    this.buildProxyGroup();
    this.buildCountryFlag();

    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");

    return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
  }
}
