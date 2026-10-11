# Third-party notices

ScamSignal's original source is distributed under the MIT licence in `LICENSE`. That licence does not relicense third-party packages, tools, fonts, or evaluation inputs. Their copyright and licence notices remain applicable.

## Runtime and development dependencies

| Component | Tested version | Licence | Upstream |
|---|---|---|---|
| React and React DOM | 19.3.0 | MIT | [React](https://github.com/facebook/react) |
| Vite | 7.3.7 | MIT | [Vite](https://github.com/vitejs/vite) |
| Vite React plugin | 4.7.0 | MIT | [Plugin](https://github.com/vitejs/vite-plugin-react) |
| Lucide React | 0.468.0 | ISC | [Lucide](https://github.com/lucide-icons/lucide) |
| Arkiv TypeScript SDK | 0.8.1 | MIT | [SDK](https://github.com/Arkiv-Network/arkiv-sdk-js) |
| viem | 2.57.4 | MIT | [viem](https://github.com/wevm/viem) |
| Zod | 4.6.5 | MIT | [Zod](https://github.com/colinhacks/zod) |
| Androguard | 4.1.4 | Apache-2.0 | [Androguard](https://github.com/androguard/androguard) |
| FastAPI | 0.143.0 | MIT | [FastAPI](https://github.com/fastapi/fastapi) |
| Starlette | 1.7.0 | BSD-3-Clause | [Starlette](https://github.com/Kludex/starlette) |
| Uvicorn | 0.54.0 | BSD-3-Clause | [Uvicorn](https://github.com/Kludex/uvicorn) |
| python-multipart | 0.0.32 | Apache-2.0 | [python-multipart](https://github.com/Kludex/python-multipart) |
| Android `apksigner` | Build Tools 35.0.0 | Apache-2.0 / Android SDK terms | [Android documentation](https://developer.android.com/tools/apksigner) |
| Playwright | 1.64.0 | Apache-2.0 | [Playwright](https://github.com/microsoft/playwright) |
| TypeScript | 5.9.3 | Apache-2.0 | [TypeScript](https://github.com/microsoft/TypeScript) |
| Vitest | 5.0.3 | MIT | [Vitest](https://github.com/vitest-dev/vitest) |

The JavaScript lockfile and Python lockfile record the full resolved dependency graph. This table identifies direct components; installed packages carry notices for their own transitive dependencies. Copies of direct runtime dependency licence texts are retained under [`apps/web/public/licenses`](apps/web/public/licenses).

DM Sans and Noto Sans Devanagari are self-hosted WOFF2 subsets obtained from Google Fonts and distributed under the SIL Open Font License 1.1. Their complete licence texts are retained in `apps/web/public/licenses/dm-sans-OFL.txt` and `noto-sans-devanagari-OFL.txt`. See [DM Sans](https://github.com/google/fonts/tree/main/ofl/dmsans) and [Noto Sans Devanagari](https://github.com/google/fonts/tree/main/ofl/notosansdevanagari). Original brand imagery and presentation visuals are project assets; sampled application names and trademarks remain their owners' property.

## Optional research tooling

The operator-only twelve-input reproduction command uses these additional packages. They are excluded from the production scanner deployment. Version-specific upstream licence texts were checked; installing these packages retains their own notices and those of their dependencies.

| Component | Tested version | Licence | Version-specific upstream licence |
|---|---|---|---|
| HTTPX | 0.28.1 | BSD-3-Clause | [Licence](https://github.com/encode/httpx/blob/0.28.1/LICENSE.md) |
| pyzipper | 0.4.0 | MIT | [Licence](https://github.com/danifus/pyzipper/blob/v0.4.0/LICENSE) |
| PyCryptodomex, required by pyzipper | 3.24.0 | BSD-2-Clause and public-domain portions | [Licence](https://github.com/Legrandin/pycryptodome/blob/v3.24.0/LICENSE.rst) |

`requirements-research.txt` pins HTTPX and pyzipper. PyCryptodomex 3.24.0 is the version resolved in the tested environment; this optional dependency graph has no separate complete lockfile. The PyCryptodome upstream licence distinguishes original PyCrypto public-domain code from direct contributions under BSD-2-Clause.

## APK evaluation inputs

The five upstream releases and two training controls were downloaded from their original public sources. Five historical malicious specimens came from a separately cited research collection and were matched to exact digests in primary research. All twelve were used only for static evaluation; they were not installed, executed, modified, or incorporated into ScamSignal's code. Their APKs are excluded from this repository and deployment. Source references, exact APK hashes, signing fingerprints, and extracted results are recorded in [`scanner/evaluation.json`](scanner/evaluation.json).

| Application | Licence | Source and licence |
|---|---|---|
| KeePassDX 4.5.5 libre | GPL-3.0 | [Release](https://github.com/Kunzisoft/KeePassDX/releases/tag/4.5.5), [licence](https://github.com/Kunzisoft/KeePassDX/blob/master/LICENSE) |
| Aegis 3.4.3 | GPL-3.0 | [Release](https://github.com/beemdevelopment/Aegis/releases/tag/v3.4.3), [licence](https://github.com/beemdevelopment/Aegis/blob/master/LICENSE) |
| NewPipe 0.29.1 | GPL-3.0 | [Release](https://github.com/TeamNewPipe/NewPipe/releases/tag/v0.29.1), [licence](https://github.com/TeamNewPipe/NewPipe/blob/dev/LICENSE) |
| Fossify Calculator 1.4.0 | GPL-3.0 | [Release](https://github.com/FossifyOrg/Calculator/releases/tag/1.4.0), [release licence](https://github.com/FossifyOrg/Calculator/blob/1.4.0/LICENSE) |
| Fossify File Manager 1.6.2 | GPL-3.0 | [Release](https://github.com/FossifyOrg/File-Manager/releases/tag/1.6.2), [release licence](https://github.com/FossifyOrg/File-Manager/blob/1.6.2/LICENSE) |
| InsecureBankv2, commit `3c8cc3a` | MIT | [Source](https://github.com/dineshshetty/Android-InsecureBankv2/tree/3c8cc3a3ce45ed56d0f58f236b541b41f992e51f), [licence](https://github.com/dineshshetty/Android-InsecureBankv2/blob/master/LICENSE) |
| PIVAA, commit `7fde895` | GPL-3.0 | [Source](https://github.com/HTBridge/pivaa/tree/7fde8956083ec4c6023c75f013f72023d60eda12), [licence](https://github.com/HTBridge/pivaa/blob/master/LICENSE) |

InsecureBankv2 and PIVAA are purpose-built insecure training applications. The evaluation does not label their authors malicious and does not establish that either APK is a scam. None of these projects endorses ScamSignal.

## Historical malware research provenance

The specimen source is the public research collection [`sk3ptre/AndroidMalware_2019`](https://github.com/sk3ptre/AndroidMalware_2019/blob/eef650faedacb06f11a778fb1e3a18bae4e5af36/README.md), pinned at commit `eef650faedacb06f11a778fb1e3a18bae4e5af36`. Its original password-protected archives are private evaluation inputs. A binary redistribution licence has **not been established** for these malicious APKs; neither this repository's MIT licence nor the licences of analysis tools apply to them. ScamSignal distributes no malicious APKs or specimen archives. Public evidence consists of sanitized technical metadata, exact digests, source attribution, and project-authored summaries.

| Evaluated specimen(s) | Primary research attribution | Exact digest evidence |
|---|---|---|
| Exodus One, package `operatore.italia` | Security Without Borders, [Exodus: New Android Spyware Made in Italy](https://github.com/securitywithoutborders/website/blob/f5d6c338a4dd373720dcaea2b138250fce6b3bb5/source/blog/posts/2019-03-29-exodus.html.markdown), 29 March 2019; pinned original website source | SHA-256 in the original report's IOC list |
| Fake MetaMask, package `com.lemon.metamask` | ESET / WeLiveSecurity, [First clipper malware discovered on Google Play](https://www.welivesecurity.com/2019/02/08/first-clipper-malware-google-play/), 8 February 2019 | MD5 in the original report's IOC list |
| Fake BtcTurk, Fake BtcTurk beta, and Fake Koineks, three distinct packages | ESET / WeLiveSecurity, [Malware sidesteps Google permissions policy with new 2FA bypass](https://www.welivesecurity.com/2019/06/17/malware-google-permissions-2fa-bypass/), 17 June 2019 | Three distinct MD5 values in the original report's IOC list |

The five unique malicious APKs span three documented campaigns/families, not five independent families. Classification is attributed to the cited primary research and exact specimen digests. Our manifest and signature checks do not reproduce the researchers' behavioral findings, establish present-day campaign activity, or measure general malware detection accuracy. Research articles and their images retain their authors' rights; full articles and research imagery are not reproduced here.
