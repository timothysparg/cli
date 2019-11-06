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
import * as fs from "fs-extra";
import * as inquirer from "inquirer";
import * as yaml from "js-yaml";
import { DeepPartial } from "ts-essentials";
import { maskString } from "./config";
import { KubeCryptOptions } from "./kubeCrypt";
import * as print from "./print";

/**
 * Handle the literal or file secret parameter from the cli
 * @param opts file or literal of KubeCryptOptions
 * @throws error if the yaml cannot be loaded
 * @returns secret
 */
export async function handleSecretParameter(opts: Pick<KubeCryptOptions, "file" | "literal" | "action">): Promise<DeepPartial<k8s.V1Secret>> {
    let secret: DeepPartial<k8s.V1Secret>;
    const literalProp = `literal-${guid()}`;
    if (opts.literal) {
        secret = wrapLiteral(opts.literal, literalProp);
    } else if (opts.file) {
        const secretString = await fs.readFile(opts.file, "utf8");
        secret = await yaml.safeLoad(secretString);
    } else {
        const answers = await inquirer.prompt<Record<string, string>>([{
            type: "input",
            name: "literal",
            message: `Enter literal string to be ${opts.action}ed:`,
        }]);
        secret = wrapLiteral(answers.literal, literalProp);
    }
    return secret;
}

/**
 * Handle the secret key parameter from the cli
 * @param opts secretKey from KubeCryptOptions
 * @returns the secret
 */
export async function handleSecretKeyParameter(opts: Pick<KubeCryptOptions, "secretKey">): Promise<string> {
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
    return opts.secretKey;
}

/**
 *  Creates a k8s.V1Secret with the input in the data section.
 * @param literal String to wrap in k8s.V1Secret
 * @param prop property name
 * @returns the k8s.V1Secret
 */
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
 * Does the requested encryption/decryption of the provided secret
 * @param input the secret to encrypt/decrypt
 * @param key the secret key to encrypt/decrypt with
 * @return the encrypted/decrypted secret
 */
export async function crypt(input: DeepPartial<k8s.V1Secret>,
                            opts: Pick<KubeCryptOptions, "action" | "secretKey">): Promise<DeepPartial<k8s.V1Secret>> {

    let secret: DeepPartial<k8s.V1Secret>;
    if (opts.action === "encrypt") {
        secret = await encryptSecret(input, opts.secretKey);
    } else {
        secret = await decryptSecret(input, opts.secretKey);
    }

    return secret;
}

/**
 * Encodes or decodes the data section of a secret
 * @param secret The secret to encode/decode
 * @param action encode or decode
 */
export function base64(secret: DeepPartial<k8s.V1Secret>, action: "encode" | "decode"): DeepPartial<k8s.V1Secret> {
    for (const datum of Object.keys(secret.data)) {
        const encoding = action === "encode" ?
            Buffer.from(secret.data[datum]).toString("base64") : Buffer.from(secret.data[datum], "base64").toString();
        secret.data[datum] = encoding;
    }
    return secret;
}

/**
 * prints the secret to the output
 * @param secret the secret to print
 * @param opts literal or file from KubeCryptOptions
 */
export function printSecret(secret: DeepPartial<k8s.V1Secret>, opts: Pick<KubeCryptOptions, "literal" | "file">): void {
    if (opts.literal) {
        print.log(secret.data[0]);
    } else if (/\.ya?ml$/.test(opts.file)) {
        print.log(yaml.safeDump(secret));
    } else {
        print.log(JSON.stringify(secret, undefined, 2));
    }
}

/**
 * writes the secret to file
 * @param secret the secret to write
 * @param opts file from KubeCryptOptions
 */
export async function writeSecret(secret: DeepPartial<k8s.V1Secret>, opts: Pick<KubeCryptOptions, "file">): Promise<void> {
    const dumpString = /\.ya?ml$/.test(opts.file) ? yaml.safeDump(secret) : JSON.stringify(secret, undefined, 2);
    await fs.writeFile(opts.file, dumpString);
}
