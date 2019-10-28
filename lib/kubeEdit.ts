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

// import { spawnPromise } from "@atomist/sdm";
import * as k8s from "@kubernetes/client-node";
import * as fs from "fs-extra";
import * as yaml from "js-yaml";
import * as _ from "lodash";
import * as tempy from "tempy";
import { DeepPartial } from "ts-essentials";
import { KubeCryptOptions } from "./kubeCrypt";
import {
    cryptEncode,
    handleSecretKeyParameter,
    handleSecretParameter,
    printSecret,
} from "./kubeUtils";
import * as print from "./print";
import { spawnSync } from "child_process";

type kubeEditOptions = Omit<KubeCryptOptions, "action">;

export async function kubeEdit(opts: kubeEditOptions): Promise<number> {
    let secret: DeepPartial<k8s.V1Secret>;
    try {
        const action: Pick<KubeCryptOptions, "action"> = {action: "decrypt"};
        secret = await handleSecretParameter(Object.assign(opts, action));
    } catch (e) {
        print.error(`Failed to load secret spec from file '${opts.file}': ${e.message}`);
        return 2;
    }
    opts.secretKey = await handleSecretKeyParameter(opts);
    // print.info(`secret=${opts.secretKey}`);
    print.log(yaml.safeDump(secret));

    try {
        secret = await cryptEncode(secret, opts.secretKey, false, opts.base64);
    } catch (e) {
        print.error(`Failed to decrypt secret: ${e.message}`);
        return 3;
    }

    try {
        secret = await edit(secret);
    } catch (e) {
        print.error(`Edit cancelled, ${e.message}`);
        return 4;
    }

    try {
        secret = await cryptEncode(secret, opts.secretKey, true, opts.base64);
        printSecret(secret, opts);
    } catch (e) {
        print.error(`Failed to encrpyt secret: ${e.message}`);
        return 3;
    }

    return 0;
}

/**
 * Opens the secret in the editor and validates that the resulting secret is valid yaml.
 * If the secret is not valid the editor is reopened.
 * @param inputSecret the secret to be edited
 * @returns the secret after the user has edited it in the editor
 */
async function edit(inputSecret: DeepPartial<k8s.V1Secret>): Promise<DeepPartial<k8s.V1Secret>> {
    const comment =
        `# Please edit the secret below. Lines beginning with a '#' will be ignored.
# An empty file will abort the edit.
# If an error occurs while saving the editor will be reopened with the relevant failures.
#\n`;

    let errorMessage = "";
    let outputSecret = _.cloneDeep(inputSecret);
    let secretText = yaml.safeDump(outputSecret);
    do {
        // join everything together to present it to the user
        secretText = comment + errorMessage + secretText;

        secretText = await openEditor(secretText);
        // remove all lines that start with comments
        secretText = secretText.replace(/^#.*\n?/gm, "");
        if (!secretText.trim()) {
            throw new Error("file is empty");
        }

        try {
            outputSecret = await yaml.safeLoad(secretText);
            errorMessage = "";
        } catch (e) {
            errorMessage = `# ${e.message.replace(/\n/gm, "\n# ")} \n`;
        }
    } while (errorMessage);

    return outputSecret;
}

/**
 * Writes the string to a temporary file and then opens the the default editor or `vi`.
 * @param fileText the contents of the file
 * @returns the string contents of the processed file
 */
async function openEditor(fileText: string): Promise<string> {
    const tmpFile = tempy.file();
    try {
        fs.writeFileSync(tmpFile, fileText);
        spawnSync(process.env.EDITOR || "vi", [tmpFile], {
            stdio: "inherit",
        });

        return fs.readFileSync(tmpFile, "utf8");
    } finally {
        fs.removeSync(tmpFile);
    }
}
