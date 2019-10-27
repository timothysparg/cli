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

import * as k8s from "@kubernetes/client-node";
import * as _ from "lodash";
import { DeepPartial } from "ts-essentials";
import {
    cryptEncode,
    handleSecretKeyParameter,
    handleSecretParameter,
    printSecret,
} from "./kubeUtils";
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
    try {
        secret = await handleSecretParameter(opts);
    } catch (e) {
        print.error(`Failed to load secret spec from file '${opts.file}': ${e.message}`);
        return 2;
    }
    opts.secretKey = await handleSecretKeyParameter(opts);

    try {
        const transformed = await cryptEncode(secret, opts.secretKey, opts.action === "encrypt", opts.base64);
        printSecret(transformed, opts);
    } catch (e) {
        print.error(`Failed to ${opts.action} secret: ${e.message}`);
        return 3;
    }

    return 0;
}
