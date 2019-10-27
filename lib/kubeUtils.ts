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
