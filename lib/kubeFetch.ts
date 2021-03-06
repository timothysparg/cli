/*
 * Copyright © 2019 Atomist, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
    kubernetesFetch,
    KubernetesFetchOptions,
    kubernetesSpecFileBasename,
    kubernetesSpecStringify,
} from "@atomist/sdm-pack-k8s";
import * as fs from "fs-extra";
import * as path from "path";
import * as print from "./print";

/**
 * Command-line options and arguments for kube-fetch.
 */
export interface KubeFetchOptions {
    /** Path to Kubernetes fetch options file. */
    optionsFile?: string;
    /** Path to directory to write spec files in. */
    outputDir?: string;
    /** Format, either "json" or "yaml", of the created files, "yaml" is the default. */
    outputFormat?: "json" | "yaml";
    /** Encryption key to use for secrets. */
    secretKey?: string;
}

/**
 * Fetch Kubernetes resources from the currently configured Kuberenetes
 * cluster, remove Kubernetes system-provided properties, and write the
 * resource specifications to files.
 *
 * @param opts see KubeFetchOptions
 * @return integer return value, 0 if successful, non-zero otherwise
 */
export async function kubeFetch(opts: KubeFetchOptions): Promise<number> {
    let outDir: string;
    if (opts.outputDir) {
        try {
            await fs.ensureDir(opts.outputDir);
        } catch (e) {
            print.error(`Failed to create output directory '${opts.outputDir}': ${e.message}`);
            return 1;
        }
        outDir = opts.outputDir;
    } else {
        outDir = process.cwd();
    }
    const fileFormat = (opts.outputFormat && opts.outputFormat.toLowerCase() === "json") ? "json" : "yaml";
    let options: KubernetesFetchOptions;
    if (opts.optionsFile) {
        try {
            options = await fs.readJson(opts.optionsFile);
        } catch (e) {
            print.error(`Failed to read Kubernetes fetch options file '${opts.optionsFile}': ${e.message}`);
            return 2;
        }
    }
    const errs: string[] = [];
    print.log("Fetching Kubernetes resources...");
    try {
        const resources = await kubernetesFetch(options);
        for (const spec of resources) {
            const specPath = path.join(outDir, kubernetesSpecFileBasename(spec) + "." + fileFormat);
            print.log(`Writing Kubernetes spec: ${specPath}`);
            try {
                const specString = await kubernetesSpecStringify(spec, { format: fileFormat, secretKey: opts.secretKey });
                await fs.writeFile(specPath, specString);
            } catch (e) {
                errs.push(`'${specPath}': ${e.message}`);
            }
        }
    } catch (e) {
        print.error(`Failed to fetch Kubernetes resources: ${e.message}`);
        return 3;
    }
    if (errs.length > 0) {
        const s = (errs.length > 1) ? "s" : "";
        print.error(`Failed to write Kubernetes spec file${s}: ${errs.join(", ")}`);
        return 10 + errs.length;
    }

    return 0;
}
