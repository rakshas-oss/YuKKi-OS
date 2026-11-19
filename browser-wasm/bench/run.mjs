#!/usr/bin/env node
/**
 * Run data-driven measurements against the actual browser-WASM module.
 *
 * Build first:
 *   cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown
 *
 * Then:
 *   node browser-wasm/bench/run.mjs --dataset browser-wasm/bench/datasets/multivariate-v1.json
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const MAX_ITERATIONS = 1000;
const MAX_OPERATIONS = 1024;
const MAX_ENTITIES = 512;
const defaults = {
  dataset: resolve(scriptDir, "datasets/multivariate-v1.json"),
  wasm: resolve(scriptDir, "../target/wasm32-unknown-unknown/release/yukki_browser_core.wasm"),
  output: null,
  iterations: null,
  operations: null,
  quick: false
};

function parseArgs(argv) {
  const options = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--quick") options.quick = true;
    else if (["--dataset", "--wasm", "--output", "--iterations", "--operations"].includes(arg)) {
      if (!argv[i + 1]) throw new Error("Missing value for " + arg);
      const value = argv[++i];
      const key = arg.slice(2);
      if (key === "iterations" || key === "operations") {
        const number = Number(value);
        const maximum = key === "iterations" ? MAX_ITERATIONS : MAX_OPERATIONS;
        if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
          throw new Error(arg + " must be an integer in 1.." + maximum);
        }
        options[key] = number;
      } else {
        options[key] = resolve(process.cwd(), value);
      }
    } else {
      throw new Error("Unknown argument: " + arg);
    }
  }
  return options;
}

function requireFunction(exports, name) {
  if (typeof exports[name] !== "function") {
    throw new Error("WASM module is missing required export " + name);
  }
}

function quantile(sorted, fraction) {
  const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index];
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

function measure(name, operationsPerSample, work, options) {
  const iterations = options.iterations;
  const warmups = Math.min(3, Math.max(1, Math.floor(iterations / 3)));
  for (let i = 0; i < warmups; i += 1) {
    options.prepare?.();
    work();
  }

  const samplesMs = [];
  let lastResult;
  for (let i = 0; i < iterations; i += 1) {
    options.prepare?.();
    const start = process.hrtime.bigint();
    lastResult = work();
    const elapsedNs = Number(process.hrtime.bigint() - start);
    samplesMs.push(elapsedNs / 1e6);
  }
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const medianBatchMs = median(samplesMs);
  const p95BatchMs = quantile(sorted, 0.95);
  const medianNsPerOperation = (medianBatchMs * 1e6) / operationsPerSample;
  return {
    benchmark: name,
    iterations,
    operations_per_sample: operationsPerSample,
    median_batch_ms: Number(medianBatchMs.toFixed(6)),
    p95_batch_ms: Number(p95BatchMs.toFixed(6)),
    median_ns_per_operation: Number(medianNsPerOperation.toFixed(2)),
    operations_per_second: Number((operationsPerSample / (medianBatchMs / 1000)).toFixed(2)),
    last_sample_result: lastResult
  };
}

function attributeValue(rule, index) {
  if (rule.kind === "linear") return rule.base + rule.step * index;
  if (rule.kind === "categorical") return rule.values[index % rule.values.length];
  if (rule.kind === "constant") return rule.value;
  throw new Error("Unsupported attribute generator kind: " + rule.kind);
}

function makeRecords(profile, count) {
  const origin = profile.origin;
  const records = [];
  const baseNs = BigInt(profile.base_timestamp_ns);
  const intervalNs = BigInt(profile.timestamp_interval_ns);
  for (let i = 0; i < count; i += 1) {
    const row = i % 32;
    const column = Math.floor(i / 32);
    const phase = i + profile.seed;
    const latitude = origin.latitude_deg
      + ((row - 15.5) + Math.sin(phase * 0.11) * 0.3) * profile.grid_step_degrees
      + Math.sin(phase * 0.07) * profile.jitter_degrees;
    const longitude = origin.longitude_deg
      + ((column - 7.5) + Math.cos(phase * 0.09) * 0.3) * profile.grid_step_degrees
      + Math.cos(phase * 0.05) * profile.jitter_degrees;
    const attributes = {};
    for (const rule of profile.attributes) {
      attributes[rule.name] = attributeValue(rule, i);
    }
    records.push({
      id: profile.seed * 100000 + i + 1,
      latitude_deg: latitude,
      longitude_deg: longitude,
      altitude_m: origin.altitude_m + (i % 23) * 0.25,
      timestamp_ns: (baseNs + BigInt(i) * intervalNs).toString(),
      radius_m: profile.radius_m,
      attributes
    });
  }
  return records;
}

function makePath(profile, count, stepDegrees) {
  const origin = profile.origin;
  const midpoint = Math.floor((count - 1) / 2);
  const points = [];
  for (let i = 0; i < count; i += 1) {
    const northSteps = Math.min(i, midpoint);
    const eastSteps = Math.max(0, i - midpoint);
    points.push({
      latitude_deg: origin.latitude_deg + northSteps * stepDegrees,
      longitude_deg: origin.longitude_deg + eastSteps * stepDegrees,
      altitude_m: origin.altitude_m
    });
  }
  return points;
}

function loadEntities(exports, records) {
  exports.adi_mmo_reset();
  for (const record of records) {
    const status = exports.adi_mmo_upsert_entity(
      record.id,
      record.latitude_deg,
      record.longitude_deg,
      record.altitude_m,
      BigInt(record.timestamp_ns),
      record.radius_m
    );
    if (status !== 0) throw new Error("WASM entity insertion failed with status " + status);
  }
  if (exports.adi_mmo_entity_count() !== records.length) {
    throw new Error("WASM entity count did not match the fixture record count");
  }
}

function readVec3(exports, pointer) {
  if (pointer === 0) throw new Error("WASM vector function returned a null pointer");
  const values = new Float64Array(exports.memory.buffer, pointer, 3);
  const vector = [values[0], values[1], values[2]];
  if (!vector.every(Number.isFinite)) throw new Error("WASM vector contained a non-finite value");
  return vector;
}

function preparePath(exports, points) {
  exports.adi_mmo_simplify_reset();
  for (const point of points) {
    const status = exports.adi_mmo_simplify_push_wgs84(
      point.latitude_deg,
      point.longitude_deg,
      point.altitude_m
    );
    if (status !== 0) throw new Error("WASM path insertion failed with status " + status);
  }
  if (exports.adi_mmo_simplify_input_count() !== points.length) {
    throw new Error("WASM path input count did not match the fixture");
  }
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || manifest.schema_version !== 1 ||
      !Array.isArray(manifest.datasets) || manifest.datasets.length < 1 ||
      manifest.datasets.length > 64) {
    throw new Error("Unsupported browser benchmark dataset schema");
  }
  const limits = manifest.limits;
  const defaults = manifest.runner_defaults;
  if (!limits || !Number.isInteger(limits.max_entities) || limits.max_entities < 1 ||
      limits.max_entities > MAX_ENTITIES || !Number.isInteger(limits.max_path_points) ||
      limits.max_path_points < 1 || limits.max_path_points > MAX_ENTITIES ||
      !Array.isArray(limits.benchmark_sizes) || limits.benchmark_sizes.length < 1 ||
      limits.benchmark_sizes.length > 8) {
    throw new Error("Invalid or unsafe browser benchmark limits");
  }
  const sizes = new Set();
  for (const size of limits.benchmark_sizes) {
    if (!Number.isInteger(size) || size < 1 || size > limits.max_entities ||
        size > limits.max_path_points || sizes.has(size)) {
      throw new Error("Benchmark sizes must be unique positive values within fixed WASM capacity");
    }
    sizes.add(size);
  }
  const positive = ["iterations", "operations_per_sample", "maximum_distance_m",
    "path_step_degrees", "path_tolerance_m"];
  for (const key of positive) {
    if (!Number.isFinite(defaults?.[key]) || defaults[key] <= 0) {
      throw new Error("Invalid " + key);
    }
  }
  const u64Max = (1n << 64n) - 1n;
  if (typeof defaults.maximum_observation_age_ns !== "string" ||
      !/^[0-9]+$/.test(defaults.maximum_observation_age_ns) ||
      BigInt(defaults.maximum_observation_age_ns) <= 0n ||
      BigInt(defaults.maximum_observation_age_ns) > u64Max ||
      defaults.iterations > MAX_ITERATIONS || defaults.operations_per_sample > MAX_OPERATIONS ||
      !Number.isFinite(defaults.bounding_box_padding_degrees) ||
      defaults.bounding_box_padding_degrees <= 0 ||
      !Number.isFinite(defaults.path_max_turn_degrees) ||
      defaults.path_max_turn_degrees <= 0 || defaults.path_max_turn_degrees > 180) {
    throw new Error("Browser benchmark runner defaults exceed supported bounds");
  }
  const ids = new Set();
  for (const profile of manifest.datasets) {
    if (!profile || typeof profile.id !== "string" || !profile.id || ids.has(profile.id) ||
        !Number.isSafeInteger(profile.seed) || profile.seed < 0 ||
        profile.seed > Math.floor((Number.MAX_SAFE_INTEGER - MAX_ENTITIES) / 100000) || !profile.origin ||
        !Number.isFinite(profile.origin.latitude_deg) || Math.abs(profile.origin.latitude_deg) > 90 ||
        !Number.isFinite(profile.origin.longitude_deg) || Math.abs(profile.origin.longitude_deg) > 180 ||
        !Number.isFinite(profile.origin.altitude_m) || Math.abs(profile.origin.altitude_m) > 1e7 ||
        !Number.isFinite(profile.grid_step_degrees) || profile.grid_step_degrees <= 0 ||
        profile.grid_step_degrees > 1 || !Number.isFinite(profile.jitter_degrees) ||
        profile.jitter_degrees < 0 || profile.jitter_degrees > 1 ||
        !Number.isFinite(profile.radius_m) || profile.radius_m <= 0 || profile.radius_m > 1e7 ||
        typeof profile.base_timestamp_ns !== "string" || !/^[0-9]+$/.test(profile.base_timestamp_ns) ||
        typeof profile.timestamp_interval_ns !== "string" || !/^[0-9]+$/.test(profile.timestamp_interval_ns) ||
        BigInt(profile.timestamp_interval_ns) <= 0n || BigInt(profile.base_timestamp_ns) > u64Max ||
        BigInt(profile.timestamp_interval_ns) > u64Max || BigInt(profile.base_timestamp_ns) +
          BigInt(profile.timestamp_interval_ns) * BigInt(MAX_ENTITIES + 2) > u64Max ||
        !Array.isArray(profile.attributes) ||
        profile.attributes.length < 1 || profile.attributes.length > 64) {
      throw new Error("Invalid or duplicate browser benchmark dataset profile");
    }
    ids.add(profile.id);
    const names = new Set();
    for (const attribute of profile.attributes) {
      if (!attribute || typeof attribute.name !== "string" || !attribute.name ||
          names.has(attribute.name)) throw new Error("Invalid or duplicate dataset attribute");
      names.add(attribute.name);
      if (attribute.kind === "linear") {
        if (!Number.isFinite(attribute.base) || !Number.isFinite(attribute.step))
          throw new Error("Invalid linear attribute generator");
      } else if (attribute.kind === "categorical") {
        if (!Array.isArray(attribute.values) || attribute.values.length < 1 ||
            attribute.values.length > 256) throw new Error("Invalid categorical attribute generator");
      } else if (attribute.kind === "constant") {
        if (!Object.prototype.hasOwnProperty.call(attribute, "value"))
          throw new Error("Invalid constant attribute generator");
      } else throw new Error("Unsupported attribute generator kind: " + attribute.kind);
    }
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(await readFile(options.dataset, "utf8"));
  validateManifest(manifest);
  const bytes = await readFile(options.wasm);
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const exports = instance.exports;

  const requiredExports = [
    "memory", "adi_mmo_reset", "adi_mmo_entity_count", "adi_mmo_upsert_entity",
    "adi_mmo_query_wgs84_bbox", "adi_mmo_query_count", "adi_mmo_resolve_nearest",
    "adi_mmo_wgs84_to_ecef", "adi_mmo_wgs84_to_enu", "adi_mmo_enu_to_ecef",
    "adi_mmo_hermite_position", "adi_mmo_simplify_reset",
    "adi_mmo_simplify_push_wgs84", "adi_mmo_simplify_input_count",
    "adi_mmo_simplify_run", "adi_mmo_simplify_output_count"
  ];
  for (const name of requiredExports) {
    if (name === "memory") {
      if (!(exports.memory instanceof WebAssembly.Memory)) throw new Error("WASM memory export is missing");
    } else {
      requireFunction(exports, name);
    }
  }

  const runnerConfig = manifest.runner_defaults;
  const iterations = options.iterations ?? (options.quick ? 4 : runnerConfig.iterations);
  const operations = options.operations ?? (options.quick ? 16 : runnerConfig.operations_per_sample);
  const sizes = options.quick ? [16, 128] : manifest.limits.benchmark_sizes;
  if (iterations * operations * manifest.datasets.length * sizes.length > 5_000_000) {
    throw new Error("Requested benchmark workload exceeds the total operation budget");
  }
  const report = {
    schema_version: 1,
    dataset_id: manifest.dataset_id,
    synthetic_data: manifest.synthetic === true,
    wasm_bytes: bytes.byteLength,
    commit_sha: process.env.GITHUB_SHA ?? null,
    execution_scope: {
      wasm: "local spatial computation in Node WebAssembly runtime",
      broker_interoperability: false,
      note: "This report does not measure TCP, BRK2/WSM1, broker placement, or GPU/NPU execution."
    },
    runtime: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      os_release: process.release?.name ?? "node"
    },
    settings: { iterations, operations_per_sample: operations, entity_sizes: sizes },
    scenarios: []
  };

  let sink = 0;
  for (const profile of manifest.datasets) {
    for (const count of sizes) {
      if (count > manifest.limits.max_entities || count > manifest.limits.max_path_points) {
        throw new Error("Fixture count exceeds the WASM fixed capacity");
      }
      const records = makeRecords(profile, count);
      const path = makePath(profile, count, runnerConfig.path_step_degrees);
      const origin = profile.origin;
      const atNs = BigInt(profile.base_timestamp_ns)
        + BigInt(count + 1) * BigInt(profile.timestamp_interval_ns);
      const maxAgeNs = BigInt(runnerConfig.maximum_observation_age_ns);
      const maxDistance = runnerConfig.maximum_distance_m;
      const operationsPerSample = operations;
      const bbox = runnerConfig.bounding_box_padding_degrees;

      const results = [];
      results.push(measure("spatial_reset_and_upsert_batch", records.length, () => {
        loadEntities(exports, records);
        return exports.adi_mmo_entity_count();
      }, { iterations }));

      loadEntities(exports, records);
      results.push(measure("wgs84_bbox_query", operationsPerSample, () => {
        let matches = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const result = exports.adi_mmo_query_wgs84_bbox(
            origin.latitude_deg - bbox,
            origin.longitude_deg - bbox,
            origin.latitude_deg + bbox,
            origin.longitude_deg + bbox
          );
          if (result < 0 || result > records.length) throw new Error("WASM bounding-box query returned an invalid match count: " + result);
          matches += result;
        }
        sink += matches;
        return { total_matches: matches, final_query_count: exports.adi_mmo_query_count() };
      }, { iterations }));

      results.push(measure("spatiotemporal_nearest_observation", operationsPerSample, () => {
        let resolved = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const index = exports.adi_mmo_resolve_nearest(
            origin.latitude_deg,
            origin.longitude_deg,
            origin.altitude_m,
            atNs,
            maxAgeNs,
            maxDistance
          );
          if (index !== 0xffffffff) resolved += 1;
        }
        if (resolved !== operationsPerSample) {
          throw new Error("WASM nearest-observation resolver failed to resolve every in-range query");
        }
        sink += resolved;
        return { successful_resolutions: resolved };
      }, { iterations }));

      results.push(measure("wgs84_to_ecef", operationsPerSample, () => {
        let checksum = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const record = records[i % records.length];
          const vector = readVec3(exports, exports.adi_mmo_wgs84_to_ecef(
            record.latitude_deg, record.longitude_deg, record.altitude_m
          ));
          checksum += vector[0];
        }
        sink += checksum;
        return { checksum: Number(checksum.toFixed(4)) };
      }, { iterations }));

      results.push(measure("wgs84_to_enu", operationsPerSample, () => {
        let checksum = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const record = records[i % records.length];
          const vector = readVec3(exports, exports.adi_mmo_wgs84_to_enu(
            origin.latitude_deg, origin.longitude_deg, origin.altitude_m,
            record.latitude_deg, record.longitude_deg, record.altitude_m
          ));
          checksum += vector[0] + vector[1] + vector[2];
        }
        sink += checksum;
        return { checksum: Number(checksum.toFixed(4)) };
      }, { iterations }));

      results.push(measure("enu_to_ecef", operationsPerSample, () => {
        let checksum = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const vector = readVec3(exports, exports.adi_mmo_enu_to_ecef(
            origin.latitude_deg, origin.longitude_deg, origin.altitude_m,
            i % 50, (i % 31) - 15, 5
          ));
          checksum += vector[0];
        }
        sink += checksum;
        return { checksum: Number(checksum.toFixed(4)) };
      }, { iterations }));

      const p0 = readVec3(exports, exports.adi_mmo_wgs84_to_ecef(
        records[0].latitude_deg, records[0].longitude_deg, records[0].altitude_m
      ));
      const p1 = readVec3(exports, exports.adi_mmo_wgs84_to_ecef(
        records[records.length - 1].latitude_deg,
        records[records.length - 1].longitude_deg,
        records[records.length - 1].altitude_m
      ));
      results.push(measure("hermite_position_interpolation", operationsPerSample, () => {
        let checksum = 0;
        for (let i = 0; i < operationsPerSample; i += 1) {
          const t = (i % 101) / 100;
          const vector = readVec3(exports, exports.adi_mmo_hermite_position(
            p0[0], p0[1], p0[2], 1, 0.5, 0,
            p1[0], p1[1], p1[2], 0, 0.5, 1, t, 1
          ));
          checksum += vector[0] + vector[1] + vector[2];
        }
        sink += checksum;
        return { checksum: Number(checksum.toFixed(4)) };
      }, { iterations }));

      results.push(measure("arc_secant_tangent_path_simplification", 1, () => {
        const countReturned = exports.adi_mmo_simplify_run(
          runnerConfig.path_tolerance_m,
          runnerConfig.path_max_turn_degrees
        );
        if (countReturned < 0) throw new Error("WASM path simplifier failed: " + countReturned);
        const outputCount = exports.adi_mmo_simplify_output_count();
        if (outputCount !== countReturned || outputCount < 1 || outputCount > path.length) {
          throw new Error("WASM simplifier output count is outside the valid path bounds");
        }
        return {
          input_points: path.length,
          retained_points: outputCount,
          reduction_percent: Number(((1 - outputCount / path.length) * 100).toFixed(2))
        };
      }, {
        iterations,
        prepare: () => preparePath(exports, path)
      }));

      report.scenarios.push({
        dataset: profile.id,
        domain: profile.domain,
        entity_count: count,
        source_attributes: profile.attributes.map(attribute => attribute.name),
        source_record_attribute_count: profile.attributes.length,
        benchmark_results: results
      });
    }
  }

  report.checksum = Number(sink.toFixed(4));
  const output = JSON.stringify(report, null, 2) + "\n";
  if (options.output) {
    await mkdir(dirname(options.output), { recursive: true });
    await writeFile(options.output, output, "utf8");
    process.stdout.write("Wrote WASM benchmark report to " + options.output + "\n");
  } else {
    process.stdout.write(output);
  }
}

main().catch(error => {
  process.stderr.write((error?.stack ?? String(error)) + "\n");
  process.exitCode = 1;
});
