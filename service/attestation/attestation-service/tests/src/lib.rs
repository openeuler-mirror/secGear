/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#[cfg(test)]
mod tests {
    use rand::{distributions::Alphanumeric, Rng};
    use reqwest::blocking::Client;
    use serde_json::{json, Value};
    use std::thread;

    #[test]
    fn api_register_reference_test() {
        let request_body = json!({
            "refs":r#"{ "RIM": "7d2e49c8d29f18b748e658e7243ecf26bc292e5fee93f72af11ad9da9810142a",
                        "PRV": "cGFja2FnZSBhdHRlc3RhdGlvbgppbXBvcnQgcmVnby52MQpleHBlY3Rfa2V5cyA6"
                    }"#
        });

        let client = Client::new();
        let endpoint = "http://127.0.0.1:8080/reference";
        let res = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .unwrap();
        println!("{:?}", res);
        assert!(res.text().unwrap().contains("success"));
    }

    #[test]
    fn api_register_concurrently() {
        let mut thread_all = vec![];
        let thread_cnt = 100;
        for _i in 0..thread_cnt {
            thread_all.push(thread::spawn(|| {
                let mut request_body = json!({
                    "refs":r#"{ "RIM": "7d2e49c8d29f18b748e658e7243ecf26bc292e5fee93f72af11ad9da9810142a",
                                "PRV": "cGFja2FnZSBhdHRlc3RhdGlvbgppbXBvcnQgcmVnby52MQpleHBlY3Rfa2V5cyA6"
                    }"#
                });
                let rng = rand::thread_rng();
                request_body["value"] = Value::String(
                    rng.clone()
                        .sample_iter(&Alphanumeric)
                        .take(64)
                        .map(char::from)
                        .collect(),
                );

                let client = Client::new();
                let endpoint = "http://127.0.0.1:8080/reference";
                let res = client
                    .post(endpoint)
                    .header("Content-Type", "application/json")
                    .body(request_body.to_string())
                    .send()
                    .unwrap();
                println!("{:?}", res);
                assert!(res.text().unwrap().contains("success"));
            }));
        }
        for hd in thread_all {
            match hd.join() {
                Ok(_) => {}
                Err(_) => {
                    assert!(false)
                }
            }
        }
    }

    #[test]
    fn api_register_complex_reference_test() {
        let request_body = json!({
            "refs":r#"{"complex_ref":{"level1_1":[1,2,3],"level1_2":{"name1":"value1"}}}"#
           }
        );

        let client = Client::new();
        let endpoint = "http://127.0.0.1:8080/reference";
        let res = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .unwrap();
        println!("{:?}", res);
        assert!(res.text().unwrap().contains("success"));
    }

    #[test]
    fn api_set_policy() {
        let request_body = json!({
            "tee":"KUNPENG",
            "id": "test_policy.rego",
            "policy":"cGFja2FnZSBhdHRlc3RhdGlvbgppbXBvcnQgcmVnby52MQpleHBlY3Rfa2V5cyA6PSBbIlJJTSIsICJSUFYiXQppbnB1dF9rZXlzIDo9IG9iamVjdC5rZXlzKGlucHV0KQpvdXRwdXRbZXhpc3RdIDo9IGlucHV0W2V4aXN0XSBpZiB7CiAgICBzb21lIGV4aXN0IGluIGV4cGVjdF9rZXlzCiAgICBleGlzdCBpbiBpbnB1dF9rZXlzCn0Kb3V0cHV0W2V4aXN0XSA6PSBudWxsIGlmIHsKICAgIHNvbWUgZXhpc3QgaW4gZXhwZWN0X2tleXMKICAgIG5vdCBleGlzdCBpbiBpbnB1dF9rZXlzCn0Kb3V0cHV0WyJPdGhlciJdIDo9ICJvdGhlciIgaWYgewogICAgInRlc3QiIGluIGlucHV0X2tleXMKfQ"
           }
        );

        let client = Client::new();
        let endpoint = "http://127.0.0.1:8080/policy";
        let res = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .unwrap();
        let response = res.text().unwrap();
        println!("set policy reponse: {}", response);
        assert!(response.contains("success"));
    }

    #[test]
    fn api_get_policy() {
        let request_body = json!({
            "policy_id":"test_policy.rego"
           }
        );
        let client: Client = Client::new();
        let endpoint = "http://127.0.0.1:8080/policy";
        let res = client
            .get(endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        println!("{:?}", res.text().unwrap());
    }

    #[test]
    fn api_evaluate() {
        let request_body = json!({
            "policy_id":["test.rego", "test_policy.rego"],
            "challenge":"71oZilAy6vXCgFuRUhAYNA",
            "evidence": "eyJ0ZWUiOiJJdHJ1c3RlZSIsImV2aWRlbmNlIjoie1xuXHRcInJlcG9ydF9zaWduXCI6XHR7XG5cdFx0XCJzY2Vfbm9fYXNcIjpcdFwiQjJEUE1NbWRUT0lVN3FpNnFCc3NaOEhFN1gtRnlwQVF3Ml9zWUpjNVVoS0FIZlFUM3phZTM5cnN6TEFzaE5qOGJ5dEIyOHNTUnp2N3RXYmRPSmV3dW5Uc1pUNnJaSEFRWFFEc1k0UzloOFRIdDBPNnlnbUV6Z1MydjZkM0NpeW91MGtQanNVbzFFbHpxbU5KS0JTbFFpejNqQlVzTjZhVXo3dkM5Yllpd3FsdWpBZm9iUlBfT19OM193NGxfMmQ4T05OaWtWRHdGcE5zMjJqcVJ0ZzlxS2VvWkduZVhUSGQwYVIzMVNKTDhsRFJsOG5Ka0FLdkRFUHZ5Zl9GN0Jrd2pEYk5YM2hNdmJMLXFEWkVWT2JNdUcwYldBVGRJV0FUTDFMem9qbDRTUVNPZDNmMEc1VWg1QU9pMEJtcDZUT3ZVTG44c0FpMWkwenF3U3h3Y0U0dlJjSG56OEVwTndTcjdET2tmUXR3bkdCY21fZUZkcTYzYXAtaWN6ZWwxa2pZUFRHZXY0bEdpemt4Wm9VN3FfYTExUXJIc1dkYnppeDBaNHlpMnBWS21lUXB0TjNydmxIYXZzZXE5VTh5VXBwbkVoMnNhVzJ3QlJmS2hYSVIxRFhiTlpNOV9qUHdRNVRTanNGQXpKYTNzbWM5VkxUMlZQa2lKSzBtNzhLS19sNkQ4TVF4ZXMyU2Q1dG9fYS1hcHh1OEE2b1E5aVZXRzBkdS0xS05MUm1hbVRCcUpLZzRfQzh0Z041dUZ3ejRLMVZ2eEYtVjY5RWVEUXpRV0o0SWFQTFNCS3BzSkx1ZUZyQjk1TGNmWnhudk05OG5oQVo4QU5PQ3pFdXJSYlVlR1MwcDM2ZjUtU3BYSGlveTNSbm5rY05tYmlVb2cwbVd6T01HVTE4WTZjeFZJVGNcIlxuXHR9LFxuXHRcImFrY2VydFwiOlx0e1xuXHRcdFwic2NlX25vX2FzXCI6XHR7XG5cdFx0XHRcInNpZ25hdHVyZVwiOlx0e1xuXHRcdFx0XHRcImRya19jZXJ0XCI6XHRcIlRVbEpSV3RxUTBOQk0zRm5RWGRKUWtGblNWSkZVbU40Tnk5NE5sRkRSRnBCUmpGS2IxRkJhMkZGVFhkRVVWbEtTMjlhU1doMlkwNUJVVVZNUWxGQmQxQlVSVXhOUVd0SFFURlZSVUpvVFVOUk1EUjRSSHBCVGtKblRsWkNRVzlVUW10b01WbFlaR3hoVkVWa1RVSnpSMEV4VlVWQmVFMVZVMGhXYUdReVZuQkpSV3hWU1VaQ2VXSXlVakZaTTFGblVUQkZkMGhvWTA1TmFrMTNUbFJGTVUxVVRYbFBSRVY2VjJoalRrMTZaM2RPVkVWNFRWUk5lVTlFUlhwWGFrRTJUVkZ6ZDBOUldVUldVVkZIUlhkS1JGUnFSVkJOUVRCSFFURlZSVU5vVFVkVFNGWm9aREpXY0UxU2IzZEhRVmxFVmxGUlJFVjRSWGROYWxwSlZXdFplRTFGY3pWTlJFRTBUMVJGZUZaRVEwTkJhVWwzUkZGWlNrdHZXa2xvZG1OT1FWRkZRa0pSUVVSblowbFFRVVJEUTBGbmIwTm5aMGxDUVUxek9FTllRMXBvZGtObk1qbE1UbXRWWWxOTU9VbGljR3RaVkhSM1IyWTBLMGhYYjJoRUt6QnNPRVl3YVRGR1dIbEVibnBJYW1keU1UTnNWakp1YkZCR09XeHVVazlNWTJKSlRDdHRVVFJJYm05UVEyWXZZVXhSZFdsRFZUTkVjRXhNVG5aMFIyZFhlbXBoTW5CbFRIVlhPVWxWWkhoMGNuUlNRalV6YVdKSFRHeHdSVkl2ZEZkaVNUSk5SMmhTTldaWFptUXdSVGR4ZFM5Q1VGWnRPVlpKVDB4eFEyMVdaMWhWY0hSblVucDNPSFpIUkZSc09GSjFPRkJ4WWt0WmRucGhUbHBxYlhwek5XNUtPWGx5VW5KSksydFBaekI2TTBwWU1tTllRVzVEVVVneGVDOWlWRzlXV0dodFkybFpPVU5MTTNCR04ydDRWSGxsZUdoR1RqVXhZakp6VVdWNVEzTlhhazVsYnpsWlVGSTBTMUJ0VVVzNVJYWm5kbkpXYW5keVRuZFNMMkZwZDFKWlowbzJTelExUzNwS1FUSnNjWFZ0VmtReFUzcFlORmhtWm14RFNqRlphRkpTWTNWeWFFc3ZaRXA0UVZkUlJsa3JTV2Q0Y1V4SE9IRlFWbGM0U1RFMFpuZzJRbWxUYkZWelIzRlVRWFp5TjFWRlF6aFNWWEJWT0VsT2VUSkpaV3A1TlhOaWMyTnBSVlpsTkVkSGFqUk5PVTB2YzBaVFQzUmlOM1FyVm5GU1RsbFRTV05HYlhKVVZqVlNjbHBDVkZkU1kyeGhOM3BXVkc1NFUwNHdjR2x5UzBWWmNFOVBVV1p6UWxodU56VjNNMFpsU0RKcU5HdEpVV3RWYUVSNU9XcFhaa05sSzFONGVuQnZTMkpvVmxrd1dsbHNVRzl1U2s5QlowaEhWek5UU2tac2JpdG1Ra3BCZFdkc1RqbFphbVJ2UVZkcVZHcDRSRTB6ZFZWdGVUQjFkRFkxU20xME5uQkNkVU1yVVVwWFIySjFhQ3RFTUV0MFNVVnROVEZMVFM5RE1HUTRNME0yYm1GSk1qVmxla0o2T0ZGalpXbG5kRXg0U1UxYVprSkZWU3RYTm1aeU9HaHhWa1pDTldkRFIzVldiRzVUUTJSNmJFbDBlRXc0VldOeWVISmpRazVQWkRSMWNIZGxiMWt4ZEVOS1VUSTVXRGNyV0RjemRVVnNkVVpJUVdkTlFrRkJSMnBuV1RoM1oxbDNkMGgzV1VSV1VqQnFRa0puZDBadlFWVkZiMjh6TjFCc2VsWTVabXRuTjNFeFluZFFjek5oTkZKVWN6aDNRM2RaUkZaU01GQkNRVkZFUVdkUU5FMUdkMGREUTNOSFFWRlZSa0ozUlVKQ1JrRjNWR3BCYjBKblozSkNaMFZHUWxGamQwRnZXV05oU0ZJd1kwUnZka3g2UlhsT2VUUjNUR3BCZFUxVE9XcFpWMng2WXpOV2JFeHRhREJpVkVGcFFtZG5ja0puUlVaQ1VXTjNRVmxaVjJGSVVqQmpSRzkyVEhwRmVVNTVOSGRNYWtGMVRWUnZlVTFFVVRCTmVrRk9RbWRyY1docmFVYzVkekJDUVZGelJrRkJUME5CVVVWQlQzWlVXR1ZFWlZSVE1VNTVibEEzY0ZZMFYwdzBZMFp1UVdoaFNFbE5hbWhwYlZjM1RqbEZRblF3VTB4SFNGQXpaRGhzTTBsblYxSkZiMlpRTkZnd1JWSjFiR1J4WWxweFpucElSWEZhZG5abFZFOVNVVlZHYVdWV1ZURnJLekY0U1doRFUzbGtNMWhxVUdObGQxWkRiMFpDY0dNMlFURlFlbkJDY1dwM1kyTXpLMDFxTUdwcVNXaFpWMDAxVnl0b1VYRlJOVWhuT1RneWFWUmhNM2haTjBGc1UzaExVa2x2YkN0dU16SkpRM2hXTkUxbFQwdzNUa0ZoWVhkVlpGRkdOamh3ZHpGQk5tSmtXV2d5VjNWSWVHWXJaQ3RUWm5aVEwzZGxjVEJFV21rNGRUSnNURzFoVVZjd2JrcEVTVFUzZFcxWFEyTTNTa2d2VkZaR0wzSmlhaXRrZVhCUlJUSkJaa3h2VjNwS2JuUkRaa3d5UjI1eVlrZ3JXbkpPVHpSQ1l6RXpOWEZaU2xad1ZqTnNVSFpOYzFVeVozRk9jRFpvVmtndkt6UkJhRTQyWjFFNVYwbzFkbUprV25aT2VsZGpURlpHYzB4UlBUMFwiLFxuXHRcdFx0XHRcImRya19zaWduXCI6XHRcIkVTLUhLSUFyOTBYQ1h3ZXRfQi1pR1BmS0Uwa0VIdWczeGhnSUpRUWNRak5iSXc5bHJ4bFZaZE1XMnlIM3hfVlNMTUhfZ3RzWjVDSXRjYlpjNlVNaWhCeDRDcXVpdjZ5RG1yMlVOUmJrNGdKd2ZiNjE5em9pNkEzaThTcFpaaUctY2dQUlNGS05IdjNSV0tBbDdXaUd1SU04ZFlvdHR0eHhJT3U0bElrQWlXR2txRlpCUzJCc2JSNXVLdEl2R0hEaG1QZEh5c3JwU3lrb0loVE4wM0FpY0NNYWRFVnhzbUs5Y0pGRlFTOHg3ZlAxU0VMUHJDMFdUT0F4bjlNdFBRVXcwSnV5dzZKeXVJZU5BYjRYRV9uNjZQOU9oRXV5Y3RjajBsa3RxLUpneFFlalRVejFROHVTbVFEV2ROcUZlRTFOQWk3Zmd6YVNjd2tTc3lXa0dtckt0MFZaSnI2a0hCT0xYMFNEMElPRWJROFNRdHFieVRpRko4Uk4tMXZqb05LYjhobnpIUnpqeGJ4eGYtVW9zeWlhY3RNUVRnOUNlTi1rSVRjUDJTUVE4ZjA0OThVVkpRamFoU05OeVcxdnp6c0hXaFQyeWMtcFdwSll6YUtrXzBjdFBVT3UwazJ1VS1EbENOdFQzRkVpS0hMZWVzRmdUSUlmdFJ1Z1JoMklHSFVkcFlvTmJDVmxvRXdaLWRPY19fQ212ZTBOOVVoWWdSUUpER1VhOGRWZVhKVXZXZ2dNQXpJdEE0QUhhVlByTFRFSTRHQld5bEw5Wm1FclU5bmpXZjd3X09XcldvaUFlVm5KMl9yanhpYjVUZ3ZldXJCM3pCbEJMSTVwQ0ExbmxhT0N0aUlMM0c1dEs3N3NNXzNXeUhYSG96cFRTeTR3WG5mU0tGeHUweXROV240XCJcblx0XHRcdH0sXG5cdFx0XHRcInBheWxvYWRcIjpcdHtcblx0XHRcdFx0XCJ2ZXJzaW9uXCI6XHRcIlRFRS5SQS4xLjBcIixcblx0XHRcdFx0XCJ0aW1lc3RhbXBcIjpcdFwiOTU1ODA5NDE0MTIzNTRcIixcblx0XHRcdFx0XCJzY2VuYXJpb1wiOlx0XCJzY2Vfbm9fYXNcIixcblx0XHRcdFx0XCJzaWduX2FsZ1wiOlx0XCJQUzI1NlwiLFxuXHRcdFx0XHRcImhhc2hfYWxnXCI6XHRcIkhTMjU2XCIsXG5cdFx0XHRcdFwicXRhX2ltZ1wiOlx0XCI3V2N1ZjZLMEM0XzBUTVIwZEMyMURBdVZ2c0c2WEIySjhxZ0dtUUFHSVdzXCIsXG5cdFx0XHRcdFwicXRhX21lbVwiOlx0XCJQVXJNdENoSGRzaW1VQWZrRnZrc3Y1Z3ZHMzFSalgtbF8wb0JsLUpCZHNNXCIsXG5cdFx0XHRcdFwidGNiXCI6XHRcIlwiLFxuXHRcdFx0XHRcImFrX3B1YlwiOlx0e1xuXHRcdFx0XHRcdFwia3R5XCI6XHRcIlJTQVwiLFxuXHRcdFx0XHRcdFwiblwiOlx0XCJwUkU1OGtzdW9IeGNMMExiMWs1blNfZkt2eERZSm96anhnYlh0aVU5T0RJNFMxa1hSZ2ZBNWdiRi1BQVJkSDZZOTdzQ0t6TklBNFRZd0pVTWh0ZFlScTZZYWZrSFZLb29tUWhJYU5mSUFaMG1BWXU5V2ttS2hBNE9BRjJNX0xDMW03WVVGMlI1S2taaGxzeFUtMEo3bWwyM2Q3RFB1enI1cnJwREFDYWxqMmZtLTROVk5DMHdYTjdPaWVXSW9UdFF0Sk9DSW5aODFjZ3FWZUxhUEVUSnpmRnBtX0ZBWXgtWDlsVnlrUFVxeWNuZnVFZjJ1Tml2OVNyMHc1d1NlX1BSRmlNQmRCRGxSQllqODBsbHllbGZGb0tWeE41c1BXMENuRkJZdlA2MHV6VVNSMDZjbHZxSU4wWUotTnhEcVhMU1VrajAtZEluNHdFLTVaaU55azI1Q25mWE5tMDk1c2tOeFo4SUxYN3FIZEJkVFhKczYxQ3J1TllsUWg0S2pHZVpWZkxVWkJZaVIwZC1JbjMyWDBYakQ1QWw4OHhLNFdxWFNhdFF6N01MekhBLURKYU8ybHNKZEFxTGFqdGxnV2ZOYXBWbWd5cVB1OFFVTkhfaEhqQlhTUDRNMXEwTUFTd2JCWXlib1VVMl9CY0lSZ0pwTnNneHlRNTJibTU2aUppYVFRQ05rYU55R1FhajRxWEVodjFTQlFlYjlMSVR1dVZfRDQzLUdhS2Z3dEhWZEZiYXdvYjZFbm5yWHoxVW1fREt1dXhLU09QZ3E0MEpRanFCQllMa1J2cXJfbS1ES3BManlVb2w4MS1ldUU1bjNZejFXU1lIbG5tc1hfMEYzbFZDQktQelR5aWd5SGZvZ0hjVXNtX2tTVDFfbWdIajg2ZnZ2OVJGTFFaTFBJRVwiLFxuXHRcdFx0XHRcdFwiZVwiOlx0XCJBUUFCXCJcblx0XHRcdFx0fVxuXHRcdFx0fSxcblx0XHRcdFwiaGFuZGxlclwiOlx0XCJwcm92aXNpb25pbmctb3V0cHV0XCJcblx0XHR9XG5cdH0sXG5cdFwicGF5bG9hZFwiOlx0e1xuXHRcdFwidmVyc2lvblwiOlx0XCJURUUuUkEuMS4wXCIsXG5cdFx0XCJ0aW1lc3RhbXBcIjpcdFwiOTU1ODExNzg4NzA1MzRcIixcblx0XHRcIm5vbmNlXCI6XHRcIjcxb1ppbEF5NnZYQ2dGdVJVaEFZTkFcIixcblx0XHRcImtleVwiOlx0e1xuXHRcdFx0XCJwdWJfa2V5XCI6XHR7XG5cdFx0XHRcdFwiblwiOlx0XCJ1LUtoY1RGLTRMdVhzTUtJZ0I0a0hDMG9NbVZXOV9OUGFGRlB0ajRfSG15azd0b0psS09BMVFENFRiY0dGYUdzenk3aUhvUm9hSUphMnJ6djFuUm1tZ3JlN0lRbTZaSXN2Z3M2bm80OW4ybUJtcENOVDlacEtXemJEMjN3N2hya3VUdkY5LUlTalhMRDk4Tk1ycF9OdUxXalNCczJPV3hyWGJrdUdjU1pETXN5NjJ6dkYxclhIYXFRRmFKNXhpU3cyaGU3YS01YWFfUGpuQmtMa0VYOE1ySF9RSzBtUFI1cmFNeU85a25CVU9UT0owdUpVS3hIQ2dKSEpTU051aDY1ZUt4VlJCS3pKbzNrT0d3Z1lRdjltOEJsZUhjeWoyWlZBVUhfZFFrajRZZFQ3bjAyZ3VBam9RMVR4aHl6R250RnV1VTFTVUZDRVAwZzN3dmI5c2N4UVNmZlNacjl5WTlCMElBR1REckZ3Q0dPM3JUamF3NXJxY2FxSlprY0pkMjFIU05DNTJUOEdENHo4UWhfV05iUHNueV9sRXI5VzU5ZHBXN0FjWlJvSkZlMHhiOGhSaURwRldmOTZJdnBTT2lQZ2RNQVY5SHRjeFRoOS1pdzJiYl9kQzYtekVLS2xfTUtzWE1rSk1DdmxDazdCd3dQX1ZKVnQ2OS1pLVo0dWN3YXhOQUxCdHJfZWFQU0RPNHU2d2JDNUl1bGlPb2VvM0hEci1FQ3RwWVdWWVplVXBGTUIwZF9GU3hsT3NXQjE3QzRNT3ZzNjVtQWcwYXJNOTMyb00xeE5WUWxfYzZkS1g4alVzV1FubXpDcG5zS1JCU3UwRHFwU0JORjhNSnY4ZDR2cFRoNFU2NmhHWFhRYjVWZjdDWkpCbC05dFZRMGJHQTVhNjFfbkYxRXhtc1wiLFxuXHRcdFx0XHRcImVcIjpcdFwiQVFBQlwiLFxuXHRcdFx0XHRcImt0eVwiOlx0XCJSU0FcIlxuXHRcdFx0fSxcblx0XHRcdFwiZW5jX2tleVwiOlx0XCJWa3hVX1FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBakJBQUFBQUFBQUNBQUFBQUFBQUFBREFBQUFBQUFBQUFNQUFBQUFBQUFBQkFBQUFBQUFBQUFFQUFBQUFBQUFBRHQ1TnJxQUpocjE1N0Q5V0QyTDRCdE9nVnlXejJfQzZTLXNLc2lzb0xpakRfWmtGM29GenpnRHV1MG04XzNSRk9oc2xTV1A4MTNJTVB3SUZMRDN4MkhSOG9VbkUyYS1fT2UwY1diRGZrQUtHLUxKaS0zNzFoNWs4T25lMHV0UmhyV1lTRnBCUS1lWGlkdlJEcUg3NUFpcDlNemJ5TExYTUlvbm1LWXlXa3EzczJMWVRiX1g1UkhMSnZqVjd0cDZxS20ySnl3TzY3TUdiVGdTUzJsbzc1SGJIaVQ5dmFBZldaUFF5Y1FDMHROTlhfRUJfUUYyTWJBckpibi1UM3NaTVhya195X3RDempMYTNWZWJXS2lsUGV5aXpYWFFBb1cyc0Q5MGZybEZYazhwMU9lTGhxcWxLVml3di1rUlk0ZU5ISnJXOGVTdTZmQndLUGw4dWJUcGt3eV9ickprYmFXUVVoYVk5ZFN5Wml5bWhPZHFTTGw4dTRwRnZvd0xKdDJQanpWajhDRTNQM0M4OEtSMkdsNjRvaUF3dnk2OWVsT1E3aXRXa1VjLTZlUDR2X0paT1VOcVZUN2hCUzNKWEJ4MmxjeS0yc0lEc1FhMGhSSW10eERFZXhoendWUFJrM2xwQkFwSlljcTR6LUVHWGV6dm5Kb0NERVRHeHVMSHl3MkctRV9lY1FnTTlyVTVQOW9GTG5fSm96OFBBYkJ6ZzgwOURwc0lKM051Slp3ZkhoNkpyNHlRRXZvTHphTFhsa1VVS0IxQXhjWXphLV9tT0R6WEJnRXRHRnBpWk9UYkFoRUhSWXRzQ25paUpDbTR6Mk9nay1HY1YwdVl1cTlCZDhreGIyVnU2NTdqVG1XVGxPVVE5SnZ1bXZ4Mks3MnJyakZBdzRpVy1PSUFab2JpdmVoN1RtUjgwaFdQaThOcTlBd1BGYm9zVWZwWDUzeUNZWUNpSk15ZzUwRUpQZXBwaFduS2NReERGNUNZMjBXSkpEXzN5REJ6WEFOeDdJSmE3NUVGMGRRVm9BSXEtVW1nODJHZWMzdWdrUEtTTXl0RHZNMmZUVlRPMl9QYlJETkFlbFpoZ3VEX0hZMDhhRTVybVE0NTFPLVFlR3pnbWw3QWpNaHJBTVZwQlp1VEpneFBNRGpWaTFWZHZ2ZzlaLWVobTlwYzFENzRCQ1hwdEZFUEVFRHhjd1dvaEhkLXExVTMtczZQTVlRbUs4QzJEQ25zekUzZ0xueTZJQW9PZ19zSGJUT1Jha1dYWnlhZkNMelJ4NmxCaFlyNkZ4OHo1Y1BIOXQ1VEstcmVqVjdPTURZbWVaUFl5QmFCbE5NYzNRbVo4Tk94d0Z2bWN1MnhEMVU4cjZqSXRqR3BVdUN5RDEzRGZnZ0REVmZWem9HSldXVHROMXVLWkNfRHVQdi12blRXdFIwZjQ4cTd6dDY1WXVpVC04NFptUXQ0Q1NMTlZNb2plR2lDbXN6bVZ1Y1ExSENxcklsQVBtM243UTJDSmx6ZEdOUWZyV3FJNmU3VHo2VGg2UWVBUkZCYzM5VVI4RjlMaHpDc2dYcGI1NWRTb0E5UXVDTEswdzRWNnFjWUE5QmJkZzRlb1ZRV1J1V1ljTDlKMl92TGZON3ROSWpCa01rTmhmZDZleXk4M2JrUmpuY3p5UFh6UllKUXF2RkppN3Y3ZjhtS0lSV1VkemNPSzhDOFB6UkJvdFR6SXZqdm9XWkpfcW45OHhWVlRJTU1pYWhZRF9ldHE5cjVTeWpTR2ZHM25nVzllblJ6a2FrVDdIc1V0MjYyalpWekxITzJKUGN0X0h2T1RkVFNWeW9wZjFUYUZlY1dCSHdaMVA2NUZpcXFueFhZam9XVnZyWlc1dmg1UGgtUzBKZ2V5U0Z1NndBWldwTkhEbWtNOGhvR09PVzMzRDZUaTFYeXY1VGpvYTI3ZmlZdGdZd3RWUTBHb2RodTBYN3NxN0Y4UnVjWW55M05yYUtJSXpRaUp4ZHRlSGNzQnpxUTRDWk5JSlNuMFZzellVQkRxR0t1Y0RmeVhVXCJcblx0XHR9LFxuXHRcdFwic2NlbmFyaW9cIjpcdFwic2NlX25vX2FzXCIsXG5cdFx0XCJ1dWlkXCI6XHRcImY2OGZkNzA0LTZlYjEtNGQxNC1iMjE4LTcyMjg1MGViM2VmMFwiLFxuXHRcdFwicmVxdWVzdGVyX3V1aWRcIjpcdFwiXCIsXG5cdFx0XCJoYXNoX2FsZ1wiOlx0XCJIUzI1NlwiLFxuXHRcdFwic2lnbl9hbGdcIjpcdFwiUFMyNTZcIixcblx0XHRcInRhX21lbVwiOlx0XCJRYjkyZWUxTlRnZlVpdnlISXZuaEVZcU5IU0tLS0FPVUlzV1Y5dVl0eXA4XCIsXG5cdFx0XCJ0YV9pbWdcIjpcdFwiQW1VLXI4OHREOVhVSlMwOGhkVkJTREFySDE0WnI3UXFRQlpwLXp2WkE5a1wiLFxuXHRcdFwidGFfYXR0clwiOlx0XCJcIixcblx0XHRcInRjYlwiOlx0XCJcIlxuXHR9LFxuXHRcImhhbmRsZXJcIjpcdFwicmVwb3J0LW91dHB1dFwiXG59In0",
           }
        );
        let client = Client::new();
        let endpoint = "http://127.0.0.1:8080/attestation";
        let res = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        println!("{:?}", res.text().unwrap());
    }

    #[test]
    fn api_get_challenge() {
        let client: Client = Client::new();
        let endpoint = "http://127.0.0.1:8080/challenge";
        let res = client
            .get(endpoint)
            .send()
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        println!("{:?}", res.text().unwrap());
    }

}
