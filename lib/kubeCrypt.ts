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

import { guid } from "@atomist/automation-client";
import {
    decryptSecret,
    encryptSecret,
} from "@atomist/sdm-pack-k8s";
import * as k8s from "@kubernetes/client-node";
import * as child_process from "child_process";
import * as fs from "fs-extra";
import * as inquirer from "inquirer";
import * as yaml from "js-yaml";
import * as _ from "lodash";
import * as tempy from "tempy";
import { DeepPartial } from "ts-essentials";
import { maskString } from "./config";
import * as print from "./print";

/**
 * Command-line options and arguments for kube-decrypt and kube-encrypt.
 */
export interface KubeCryptOptions {
    /** To encrypt or decrypt? */
    action: "decrypt" | "encrypt";
    /** Path to Kubernetes secret spec file. */
    file?: string;
    /** Literal string to encrypt/decrypt. */
    literal?: string;
    /** Encryption key to use for encryption/decryption. */
    secretKey?: string;
    /** Open secret in editor */
    openEditor?: boolean;
    /** Option to Base64 encode/decode data */
    base64?: boolean;
}

/**
 * Encrypt or decrypt secret data values.
 *
 * @param opts see KubeCryptOptions
 * @return integer return value, 0 if successful, non-zero otherwise
 */
export async function kubeCrypt(opts: KubeCryptOptions): Promise<number> {
    let secret: DeepPartial<k8s.V1Secret>;
    const literalProp = `literal-${guid()}`;
    if (opts.literal) {
        secret = wrapLiteral(opts.literal, literalProp);
    } else if (opts.file) {
        try {
            const secretString = await fs.readFile(opts.file, "utf8");
            secret = await yaml.safeLoad(secretString);
        } catch (e) {
            print.error(`Failed to load secret spec from file '${opts.file}': ${e.message}`);
            return 2;
        }
    } else {
        const answers = await inquirer.prompt<Record<string, string>>([{
            type: "input",
            name: "literal",
            message: `Enter literal string to be ${opts.action}ed:`,
        }]);
        secret = wrapLiteral(answers.literal, literalProp);
    }

    if (!opts.secretKey) {
        const answers = await inquirer.prompt<Record<string, string>>([{
            type: "input",
            name: "secretKey",
            message: `Enter encryption key:`,
            transformer: maskString,
            validate: v => v.length < 1 ? "Secret key must have non-zero length" : true,
        }]);
        opts.secretKey = answers.secretKey;
    }

    if (opts.openEditor) {
        try {
            secret = await edit(secret);
        } catch (e) {
            print.error(`Edit cancelled, ${e.message}`);
            return 2;
        }
    }

    try {
        const transformed = await cryptEncode(secret, opts.secretKey, opts.action === "encrypt", opts.base64);
        if (transformed.data[literalProp]) {
            print.log(transformed.data[literalProp]);
        } else if (/\.ya?ml$/.test(opts.file)) {
            print.log(yaml.safeDump(transformed));
        } else {
            print.log(JSON.stringify(transformed, undefined, 2));
        }
    } catch (e) {
        print.error(`Failed to ${opts.action} secret: ${e.message}`);
        return 3;
    }

    return 0;
}

function wrapLiteral(literal: string, prop: string): DeepPartial<k8s.V1Secret> {
    const secret: DeepPartial<k8s.V1Secret> = {
        apiVersion: "v1",
        data: {},
        kind: "Secret",
        type: "Opaque",
    };
    secret.data[prop] = literal;
    return secret;
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
        child_process.spawnSync(process.env.EDITOR || "vi", [tmpFile], {
            stdio: "inherit",
        });
        return fs.readFileSync(tmpFile, "utf8");
    } finally {
        fs.removeSync(tmpFile);
    }
}

/**
 * Does the requested encryption/decryption of the provided secret and optionally base64 encodes/decodes the secret
 * @param input the secret to encrypt/decrypt
 * @param key the secret key to encrypt/decrypy with
 * @param b64 true to bese64 encode/decode
 * @return the encrypted/decrypted and optionally base64 encoded/decoded secret
 */
export async function cryptEncode(input: DeepPartial<k8s.V1Secret>, key: string, encrypt: boolean, b64: boolean): Promise<DeepPartial<k8s.V1Secret>> {
    const doBase64 = (s: DeepPartial<k8s.V1Secret>) => b64 ? base64(s, encrypt) : s;

    let secret: DeepPartial<k8s.V1Secret>;
    if (encrypt) {
        secret = doBase64(input);
        secret = await encryptSecret(secret, key);
    } else {
        secret = await decryptSecret(input, key);
        secret = doBase64(secret);
    }
    return secret;
}

/**
 * Encodes or decodes the data section of a secret
 * @param secret The secret to encode/decode
 * @param encode True encodes, False decodes
 */
export function base64(secret: DeepPartial<k8s.V1Secret>, encode: boolean): DeepPartial<k8s.V1Secret> {
    for (const datum of Object.keys(secret.data)) {
        const encoding = encode ? Buffer.from(secret.data[datum]).toString("base64") : Buffer.from(secret.data[datum], "base64").toString();
        secret.data[datum] = encoding;
    }
    return secret;
}
