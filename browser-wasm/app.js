const $ = (id) => document.getElementById(id);
const connectForm = $("connect-form");
const gatewayInput = $("gateway-url");
const tokenInput = $("gateway-token");
const connectButton = $("connect-button");
const disconnectButton = $("disconnect-button");
const connectionStatus = $("connection-status");
const streamList = $("stream-list");
const streamCount = $("stream-count");
const chunkForm = $("chunk-form");
const fromInput = $("from-sequence");
const limitInput = $("chunk-limit");
const readButton = $("read-button");
const autoRefreshInput = $("auto-refresh");
const chunkStatus = $("chunk-status");
const chunkList = $("chunk-list");
const selectedLabel = $("selected-stream");

let wasm = null;
let gatewayBase = "";
let bearerToken = "";
let streams = [];
let selectedStream = null;
let pollHandle = null;
let readInFlight = false;

gatewayInput.value = window.location.origin;

function setStatus(node, message, kind = "info") {
  node.textContent = message;
  node.dataset.state = kind;
}

function normalizeGatewayBase(value) {
  const url = new URL(value.trim());
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Gateway URL must use HTTPS, or HTTP on localhost for development.");
  }
  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !localHost) {
    throw new Error("Use HTTPS for remote gateways. Plain HTTP is allowed only on localhost.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Gateway URL must not contain credentials, a query, or a fragment.");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

async function loadWasm() {
  const response = await fetch(new URL("./yukki_browser_core.wasm", import.meta.url), {
    cache: "no-store",
    credentials: "omit",
    redirect: "error"
  });
  if (!response.ok) throw new Error("Unable to load the browser verifier (HTTP " + response.status + ").");
  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, {});
  wasm = result.instance.exports;
  for (const name of ["memory", "yukki_input_ptr", "yukki_input_capacity", "yukki_validate_ykmc", "adi_mmo_reset", "adi_mmo_entity_count", "adi_mmo_upsert_entity", "adi_mmo_entity_id", "adi_mmo_entity_lat", "adi_mmo_entity_lon", "adi_mmo_entity_alt", "adi_mmo_entity_timestamp_ns", "adi_mmo_resolve_nearest", "adi_mmo_wgs84_to_ecef", "adi_mmo_simplify_reset", "adi_mmo_simplify_push_wgs84", "adi_mmo_simplify_run", "adi_mmo_simplify_output_count", "adi_mmo_simplify_output_index", "adi_mmo_simplify_output_lat", "adi_mmo_simplify_output_lon", "adi_mmo_simplify_output_alt"]) {
    if (!(name in wasm)) throw new Error("Browser verifier is missing export: " + name);
  }
}

function makeYkmcFrame(chunk) {
  if (!chunk || typeof chunk !== "object") throw new Error("Chunk record is not an object.");
  if (typeof chunk.stream_id !== "string" || typeof chunk.codec !== "string") {
    throw new Error("Chunk metadata is missing a stream ID or codec.");
  }
  if (chunk.media_type !== "audio" && chunk.media_type !== "video") {
    throw new Error("Unsupported media type in chunk record.");
  }
  if (typeof chunk.is_keyframe !== "boolean" || !Array.isArray(chunk.payload)) {
    throw new Error("Chunk flags or payload have an invalid shape.");
  }
  if (chunk.payload.length > 256 * 1024) throw new Error("Chunk payload exceeds the 256 KiB limit.");

  const encoder = new TextEncoder();
  const streamId = encoder.encode(chunk.stream_id);
  const codec = encoder.encode(chunk.codec);
  if (streamId.length < 1 || streamId.length > 128) throw new Error("Stream ID length is outside the YKMC limit.");
  if (codec.length < 1 || codec.length > 64) throw new Error("Codec label length is outside the YKMC limit.");

  const toU64 = (value, label) => {
    if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
    throw new Error(label + " is not an exact non-negative integer in this browser response.");
  };
  const sequence = toU64(chunk.sequence_no, "Sequence number");
  const timestamp = toU64(chunk.timestamp_ms, "Timestamp");
  const payload = new Uint8Array(chunk.payload.length);
  for (let i = 0; i < chunk.payload.length; i += 1) {
    const byte = chunk.payload[i];
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) throw new Error("Payload contains a non-byte value.");
    payload[i] = byte;
  }

  const frame = new Uint8Array(31 + streamId.length + codec.length + payload.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, 0x594b4d43, false);
  view.setUint8(4, 1);
  view.setUint8(5, chunk.media_type === "audio" ? 0 : 1);
  view.setUint8(6, chunk.is_keyframe ? 1 : 0);
  view.setUint16(7, streamId.length, false);
  view.setUint16(9, codec.length, false);
  view.setBigUint64(11, sequence, false);
  view.setBigUint64(19, timestamp, false);
  view.setUint32(27, payload.length, false);
  frame.set(streamId, 31);
  frame.set(codec, 31 + streamId.length);
  frame.set(payload, 31 + streamId.length + codec.length);
  return { frame, sequence };
}

function verifyChunkWithWasm(chunk) {
  const { frame, sequence } = makeYkmcFrame(chunk);
  const ptr = wasm.yukki_input_ptr();
  const capacity = wasm.yukki_input_capacity();
  if (frame.length > capacity) throw new Error("Chunk exceeds the browser verifier's fixed input buffer.");
  new Uint8Array(wasm.memory.buffer, ptr, frame.length).set(frame);
  const status = wasm.yukki_validate_ykmc(frame.length);
  if (status !== 0) throw new Error("Rust WASM rejected YKMC frame (validation code " + status + ").");
  return sequence;
}

function quoteLargeProtocolIntegers(raw) {
  const targetKeys = new Set(["latest_seq", "sequence_no", "timestamp_ms"]);
  let out = "";
  let i = 0;
  while (i < raw.length) {
    if (raw[i] === '"') {
      let end = i + 1;
      while (end < raw.length) {
        if (raw[end] === "\\") {
          end += 2;
          continue;
        }
        if (raw[end] === '"') break;
        end += 1;
      }
      const token = raw.slice(i, end + 1);
      const key = token.slice(1, -1);
      out += token;
      i = end + 1;
      if (targetKeys.has(key)) {
        const match = raw.slice(i).match(/^(\s*:\s*)(\d+)(?=\s*[,}\]])/);
        if (match) {
          out += match[1] + '"' + match[2] + '"';
          i += match[0].length;
        }
      }
    } else {
      out += raw[i];
      i += 1;
    }
  }
  return out;
}

async function gatewayFetch(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(gatewayBase + path, {
      method: "GET",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/json"
      },
      signal: controller.signal
    });
    if (response.status === 401 || response.status === 403) {
      bearerToken = "";
      tokenInput.value = "";
      throw new Error("Gateway authentication failed or this browser origin is not allowed.");
    }
    if (!response.ok) {
      const error = new Error("Gateway returned HTTP " + response.status + ".");
      error.status = response.status;
      throw error;
    }
    const raw = await response.text();
    return JSON.parse(quoteLargeProtocolIntegers(raw));
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Gateway request timed out after 12 seconds.");
    if (error instanceof TypeError) {
      throw new Error("Network/CORS failure. Check the gateway URL, TLS certificate, and YUKKI_GATEWAY_CORS_ORIGINS allow-list.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function renderStreams() {
  streamList.replaceChildren();
  streamCount.textContent = streams.length + " stream(s)";
  if (streams.length === 0) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No streams are currently registered.";
    streamList.append(empty);
    return;
  }

  for (const stream of streams) {
    const card = document.createElement("article");
    card.className = "stream-card";
    const details = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = stream.name || stream.id;
    const meta = document.createElement("p");
    meta.className = "chunk-meta";
    meta.textContent = [
      stream.kind || "unknown",
      stream.status || "unknown",
      "latest seq: " + (stream.latest_seq ?? "none"),
      "origin: " + (stream.origin_node || "unknown")
    ].join(" · ");
    const id = document.createElement("p");
    id.className = "muted";
    id.textContent = stream.id;
    details.append(name, meta, id);

    const choose = document.createElement("button");
    choose.type = "button";
    choose.textContent = "Inspect";
    choose.addEventListener("click", () => selectStream(stream));
    card.append(details, choose);
    streamList.append(card);
  }
}

function stopPolling() {
  if (pollHandle !== null) {
    window.clearInterval(pollHandle);
    pollHandle = null;
  }
}

function updatePolling() {
  stopPolling();
  if (autoRefreshInput.checked && selectedStream && bearerToken) {
    pollHandle = window.setInterval(() => {
      if (!readInFlight) readChunks(true);
    }, 2000);
  }
}

function selectStream(stream) {
  selectedStream = stream;
  selectedLabel.textContent = stream.name || stream.id;
  const latest = stream.latest_seq;
  fromInput.value = latest === null || latest === undefined ? "0" : String(latest);
  limitInput.value = "1";
  readButton.disabled = false;
  autoRefreshInput.disabled = false;
  autoRefreshInput.checked = false;
  stopPolling();
  chunkList.replaceChildren();
  setStatus(chunkStatus, "Stream selected. Read a retained chunk or enable polling.");
  readChunks(false);
}

function renderChunks(chunks) {
  chunkList.replaceChildren();
  if (!Array.isArray(chunks) || chunks.length === 0) {
    const item = document.createElement("li");
    item.className = "muted";
    item.textContent = "No chunks returned for this range.";
    chunkList.append(item);
    return;
  }

  let lastSequence = null;
  for (const chunk of chunks) {
    const sequence = verifyChunkWithWasm(chunk);
    lastSequence = sequence;
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = "Sequence " + sequence.toString();
    const detail = document.createElement("p");
    detail.className = "chunk-meta";
    detail.textContent = [
      chunk.media_type,
      chunk.codec,
      chunk.payload.length + " payload bytes",
      "timestamp " + chunk.timestamp_ms + " ms",
      chunk.is_keyframe ? "keyframe" : "delta frame",
      "Rust WASM validation: passed"
    ].join(" · ");
    item.append(title, detail);
    chunkList.append(item);
  }
  if (lastSequence !== null) {
    fromInput.value = (lastSequence + 1n).toString();
  }
}

async function readChunks(fromPolling) {
  if (!selectedStream || !bearerToken || readInFlight) return;
  const fromText = fromInput.value.trim();
  if (!/^(0|[1-9][0-9]*)$/.test(fromText)) {
    setStatus(chunkStatus, "Start sequence must be an unsigned decimal integer.", "error");
    return;
  }
  const limit = Number(limitInput.value);
  if (!Number.isInteger(limit) || limit < 1 || limit > 8) {
    setStatus(chunkStatus, "Chunk limit must be between 1 and 8.", "error");
    return;
  }

  readInFlight = true;
  readButton.disabled = true;
  if (!fromPolling) setStatus(chunkStatus, "Reading bounded chunk range…");
  try {
    const path = "/v1/streams/" + encodeURIComponent(selectedStream.id) +
      "/chunks?from=" + encodeURIComponent(fromText) + "&limit=" + limit;
    const chunks = await gatewayFetch(path);
    renderChunks(chunks);
    setStatus(chunkStatus, chunks.length + " chunk(s) read and checked by the Rust WASM verifier.");
  } catch (error) {
    if (error.status === 416) {
      if (!fromPolling) setStatus(chunkStatus, "That range is not currently retained. Try a newer sequence.", "error");
    } else if (error.status === 404) {
      setStatus(chunkStatus, "The selected stream no longer exists.", "error");
      stopPolling();
    } else {
      setStatus(chunkStatus, error.message || "Unable to read chunks.", "error");
      if (!bearerToken) stopPolling();
    }
  } finally {
    readInFlight = false;
    readButton.disabled = !selectedStream || !bearerToken;
  }
}

connectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  connectButton.disabled = true;
  stopPolling();
  try {
    gatewayBase = normalizeGatewayBase(gatewayInput.value);
    bearerToken = tokenInput.value;
    tokenInput.value = "";
    if (!bearerToken) throw new Error("Enter a gateway bearer token.");
    setStatus(connectionStatus, "Authenticating and loading stream list…");
    const data = await gatewayFetch("/v1/streams");
    if (!Array.isArray(data)) throw new Error("Gateway returned an invalid stream list.");
    streams = data;
    renderStreams();
    disconnectButton.disabled = false;
    setStatus(connectionStatus, "Connected. Credentials remain in page memory only.");
  } catch (error) {
    bearerToken = "";
    streams = [];
    selectedStream = null;
    renderStreams();
    disconnectButton.disabled = true;
    readButton.disabled = true;
    autoRefreshInput.disabled = true;
    setStatus(connectionStatus, error.message || "Unable to connect.", "error");
  } finally {
    connectButton.disabled = false;
  }
});

disconnectButton.addEventListener("click", () => {
  stopPolling();
  bearerToken = "";
  gatewayBase = "";
  streams = [];
  selectedStream = null;
  tokenInput.value = "";
  renderStreams();
  chunkList.replaceChildren();
  const empty = document.createElement("li");
  empty.className = "muted";
  empty.textContent = "No chunks loaded.";
  chunkList.append(empty);
  selectedLabel.textContent = "No stream selected";
  streamCount.textContent = "Not connected";
  readButton.disabled = true;
  autoRefreshInput.checked = false;
  autoRefreshInput.disabled = true;
  disconnectButton.disabled = true;
  setStatus(connectionStatus, "Disconnected. Token cleared from page memory.");
  setStatus(chunkStatus, "Select a stream to inspect retained chunks.");
});

chunkForm.addEventListener("submit", (event) => {
  event.preventDefault();
  readChunks(false);
});
autoRefreshInput.addEventListener("change", updatePolling);

const mmoForm = $("mmo-form");
const mmoResolveForm = $("mmo-resolve-form");
const mmoResetButton = $("mmo-reset");
const mmoStatus = $("mmo-status");
const mmoEntityList = $("mmo-entity-list");
const mmoSimplifyForm = $("mmo-simplify-form");
const mmoSimplifyStatus = $("mmo-simplify-status");
const mmoSimplifyList = $("mmo-simplify-list");

function wasmVec3(pointer) {
  if (!pointer) throw new Error("WASM rejected the coordinate input.");
  // The output is a short-lived view into one shared result slot: copy it now.
  return Array.from(new Float64Array(wasm.memory.buffer, pointer, 3));
}

function renderMmoEntities() {
  mmoEntityList.replaceChildren();
  mmoSimplifyList.replaceChildren();
  wasm.adi_mmo_simplify_reset();
  const count = wasm.adi_mmo_entity_count();
  if (count === 0) {
    const empty = document.createElement("li");
    empty.className = "muted";
    empty.textContent = "No local entities loaded.";
    mmoEntityList.append(empty);
    const noPath = document.createElement("li");
    noPath.className = "muted";
    noPath.textContent = "No simplified path yet.";
    mmoSimplifyList.append(noPath);
    setStatus(mmoSimplifyStatus, "Add at least two entities to simplify a path.");
    return;
  }

  for (let index = 0; index < count; index += 1) {
    const id = wasm.adi_mmo_entity_id(index);
    const lat = wasm.adi_mmo_entity_lat(index);
    const lon = wasm.adi_mmo_entity_lon(index);
    const alt = wasm.adi_mmo_entity_alt(index);
    const timestamp = wasm.adi_mmo_entity_timestamp_ns(index);
    const pathStatus = wasm.adi_mmo_simplify_push_wgs84(lat, lon, alt);
    if (pathStatus !== 0) throw new Error("Unable to stage path coordinate in WASM (code " + pathStatus + ").");
    const ecef = wasmVec3(wasm.adi_mmo_wgs84_to_ecef(lat, lon, alt));
    const item = document.createElement("li");
    item.textContent = [
      "Entity " + id,
      "WGS84 " + lat.toFixed(6) + ", " + lon.toFixed(6) + ", " + alt.toFixed(1) + " m",
      "ECEF " + ecef.map((value) => value.toFixed(1)).join(", ") + " m",
      "observed " + timestamp.toString() + " ns"
    ].join(" · ");
    mmoEntityList.append(item);
  }
}

mmoSimplifyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const tolerance = Number($("mmo-simplify-tolerance").value);
  const maxTurn = Number($("mmo-simplify-turn").value);
  if (!Number.isFinite(tolerance) || tolerance < 0 ||
      !Number.isFinite(maxTurn) || maxTurn <= 0 || maxTurn > 180) {
    setStatus(mmoSimplifyStatus, "Enter a non-negative error tolerance and a turn limit from 1 to 180 degrees.", "error");
    return;
  }
  const inputCount = wasm.adi_mmo_simplify_input_count();
  if (inputCount < 2) {
    setStatus(mmoSimplifyStatus, "At least two ordered entity observations are required.", "error");
    return;
  }
  const result = wasm.adi_mmo_simplify_run(tolerance, maxTurn);
  if (result < 0) {
    setStatus(mmoSimplifyStatus, "WASM path simplification failed (code " + result + ").", "error");
    return;
  }
  const outputCount = wasm.adi_mmo_simplify_output_count();
  mmoSimplifyList.replaceChildren();
  for (let outputIndex = 0; outputIndex < outputCount; outputIndex += 1) {
    const originalIndex = wasm.adi_mmo_simplify_output_index(outputIndex);
    const item = document.createElement("li");
    item.textContent = [
      "Retained point " + originalIndex,
      wasm.adi_mmo_simplify_output_lat(outputIndex).toFixed(6) + ", " +
        wasm.adi_mmo_simplify_output_lon(outputIndex).toFixed(6),
      wasm.adi_mmo_simplify_output_alt(outputIndex).toFixed(1) + " m"
    ].join(" · ");
    mmoSimplifyList.append(item);
  }
  const reduction = inputCount === 0 ? 0 : (100 * (inputCount - outputCount) / inputCount);
  setStatus(mmoSimplifyStatus, outputCount + " of " + inputCount +
    " points retained (" + reduction.toFixed(1) + "% fewer). Tolerance: " +
    tolerance + " m; maximum tangent turn: " + maxTurn + "°.");
});

mmoForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const id = Number($("mmo-entity-id").value);
  const lat = Number($("mmo-lat").value);
  const lon = Number($("mmo-lon").value);
  const alt = Number($("mmo-alt").value);
  if (!Number.isSafeInteger(id) || id < 0 || id >= 0xffffffff ||
      !Number.isFinite(lat) || !Number.isFinite(lon) || !Number.isFinite(alt)) {
    setStatus(mmoStatus, "Entity ID or coordinates are outside the accepted range.", "error");
    return;
  }
  const status = wasm.adi_mmo_upsert_entity(
    id, lat, lon, alt, BigInt(Date.now()) * 1000000n, 0
  );
  if (status !== 0) {
    setStatus(mmoStatus, status === -2 ? "The 512-entity browser store is full." : "WASM rejected the entity (code " + status + ").", "error");
    return;
  }
  try {
    renderMmoEntities();
    const ecef = wasmVec3(wasm.adi_mmo_wgs84_to_ecef(lat, lon, alt));
    setStatus(mmoStatus, "Entity " + id + " stored in WASM. ECEF: " + ecef.map((value) => value.toFixed(2)).join(", ") + " m.");
  } catch (error) {
    setStatus(mmoStatus, error.message || "Unable to render the entity.", "error");
  }
});

mmoResolveForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const lat = Number($("mmo-query-lat").value);
  const lon = Number($("mmo-query-lon").value);
  const alt = Number($("mmo-query-alt").value);
  const maxAgeMs = Number($("mmo-max-age").value);
  const maxDistance = Number($("mmo-max-distance").value);
  if (![lat, lon, alt, maxAgeMs, maxDistance].every(Number.isFinite) ||
      maxAgeMs < 0 || maxAgeMs > 86400000 || maxDistance < 0) {
    setStatus(mmoStatus, "Query coordinates, age, or distance are invalid.", "error");
    return;
  }
  const nowNs = BigInt(Date.now()) * 1000000n;
  const index = wasm.adi_mmo_resolve_nearest(
    lat, lon, alt, nowNs, BigInt(Math.trunc(maxAgeMs)) * 1000000n, maxDistance
  );
  if (index === 0xffffffff) {
    setStatus(mmoStatus, "No observation matched the spatial, temporal, and distance constraints.", "error");
    return;
  }
  const id = wasm.adi_mmo_entity_id(index);
  const matchedLat = wasm.adi_mmo_entity_lat(index);
  const matchedLon = wasm.adi_mmo_entity_lon(index);
  const matchedAlt = wasm.adi_mmo_entity_alt(index);
  const observedAt = wasm.adi_mmo_entity_timestamp_ns(index);
  setStatus(mmoStatus, "Resolved entity " + id + " at " +
    matchedLat.toFixed(6) + ", " + matchedLon.toFixed(6) + ", " +
    matchedAlt.toFixed(1) + " m; observation timestamp " + observedAt.toString() + " ns.");
});

mmoResetButton.addEventListener("click", () => {
  wasm.adi_mmo_reset();
  renderMmoEntities();
  setStatus(mmoStatus, "Local WASM entity store cleared.");
});

window.addEventListener("pagehide", () => {
  stopPolling();
  bearerToken = "";
  gatewayBase = "";
});

(async () => {
  try {
    await loadWasm();
    setStatus(connectionStatus, "Rust WebAssembly verifier and MMO spatial core ready. Enter gateway credentials to connect.");
    setStatus(mmoStatus, "WASM spatial resolver ready. Add a WGS84 observation to begin.");
    renderMmoEntities();
  } catch (error) {
    connectButton.disabled = true;
    setStatus(connectionStatus, error.message || "Browser verifier failed to initialize.", "error");
  }
})();
