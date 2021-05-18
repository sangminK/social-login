package me.smkim.sociallogin;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.json.JSONParser;
import org.apache.tomcat.util.json.ParseException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Map;

@Controller
@Slf4j
public class LoginController {

    // TODO : 프로퍼티로 빼기
    private String CLIENT_ID = "L2mKR0AJefEcr4Mkkn1B";
    private String CLIENT_SECRET = "hlpi9diD19";

    @GetMapping("login")
    public String login(HttpSession session, Model model) throws UnsupportedEncodingException, UnknownHostException {
        log.info("### Login 페이지로...");

        /* 네이버 */
        /*
        * 1. 네이버 로그인 인증 요청 API
        *  - 웹 또는 앱에 네이버 로그인 화면을 띄우는 API
        *  - 이용자가 네이버 회원 인증에 성공하면, API로부터 받은 code 값을 이용해서 접근 토큰 발급 요청 API를 호출
        * 2. 접근 토큰 발급/갱신/삭제 요청 API
        *  - 접근 토큰 발급 요청 API를 통해 받은 접근 토큰(access token) 값은 회원 프로필 조회를 비롯하여 여러가지 로그인 오픈 API를 호출하는데 사용
        * */
        String redirectURI = URLEncoder.encode("http://localhost:8080/callback", "UTF-8");

        // CSRF 방지를 위한 상태 토큰 생성 코드
        // 상태 토큰은 추후 검증을 위해 세션에 저장
        SecureRandom random = new SecureRandom();
        String state = new BigInteger(130, random).toString();
        session.setAttribute("state", state);

        String apiURL = "https://nid.naver.com/oauth2.0/authorize?response_type=code";
        apiURL += String.format("&client_id=%s&redirect_uri=%s&state=%s", CLIENT_ID, redirectURI, state);

        model.addAttribute("apiURL", apiURL);

        return "login";
    }

    @GetMapping("callback")
    public String callback(HttpSession session, Model model, HttpServletRequest request) throws IOException, ParseException {
        log.info("### Callback");

        String code = request.getParameter("code");
        String state = request.getParameter("state");

        String sessionState = (String) session.getAttribute("state");
        if(!state.equals(sessionState) ) {
            // TODO
            //return RESPONSE_UNAUTHORIZED; //401 unauthorized
        }

        // 접근 토큰 요청
        String redirectURI = URLEncoder.encode("http://localhost:8080/callback", "UTF-8");
        String apiURL;
        apiURL = "https://nid.naver.com/oauth2.0/token?grant_type=authorization_code";
        apiURL += "&client_id=" + CLIENT_ID;
        apiURL += "&client_secret=" + CLIENT_SECRET;
        apiURL += "&redirect_uri=" + redirectURI;
        apiURL += "&code=" + code;
        apiURL += "&state=" + state;

        try {
            URL url = new URL(apiURL);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            int responseCode = con.getResponseCode();
            BufferedReader br;
            log.info("### ResponseCode = " + responseCode);
            if (responseCode == 200) { // 정상 호출
                br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            } else {  // 에러 발생
                br = new BufferedReader(new InputStreamReader(con.getErrorStream()));
            }

            String inputLine;
            StringBuffer res = new StringBuffer();
            while ((inputLine = br.readLine()) != null) {
                res.append(inputLine);
            }
            br.close();
            if (responseCode == 200) {
                log.info("### Res = " + res.toString());

                /* {
                    "access_token": "AAAAQosjWDJieBiQZc3to9YQp6HDLvrmyKC+6+iZ3gq7qrkqf50ljZC+Lgoqrg",
                    "refresh_token": "c8ceMEJisO4Se7uGisHoX0f5JEii7JnipglQipkOn5Zp3tyP7dHQoP0zNKHUq2gY",
                    "token_type": "bearer",
                    "expires_in": "3600"
                    } */
                Map<String, Object> resObj = new JSONParser(res.toString()).parseObject();
                session.setAttribute("access_token", resObj.get("access_token"));
                session.setAttribute("refresh_token", resObj.get("refresh_token"));
                session.setAttribute("token_type", resObj.get("token_type"));

            } else {
                log.error("### 네이버 로그인 접근 토큰 요청 실패!");
            }
        } catch (Exception e) {
            log.error("### Error = "+e);
        }
        return "callback";
    }

    /*
    * 네이버 사용자 프로필 정보 조회
    * */
    @GetMapping("naver/get/profile")
    public String getProfile(HttpSession session, Model model) {
        String access_token = (String) session.getAttribute("access_token");
        String token_type = (String) session.getAttribute("token_type");

        String apiURL = "https://openapi.naver.com/v1/nid/me";
        String headerStr = token_type + " " + access_token;

        try {
            URL url = new URL(apiURL);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("Authorization", headerStr);
            int responseCode = con.getResponseCode();
            BufferedReader br;
            log.info("### ResponseCode = " + responseCode);
            if (responseCode == 200) { // 정상 호출
                br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            } else {  // 에러 발생
                br = new BufferedReader(new InputStreamReader(con.getErrorStream()));
            }

            String inputLine;
            StringBuffer res = new StringBuffer();
            while ((inputLine = br.readLine()) != null) {
                res.append(inputLine);
            }
            br.close();
            if (responseCode == 200) {
                log.info("### Res = " + res.toString());
                // ### Res = {
                // "resultcode":"00",
                // "message":"success",
                // "response":{"id":"11978265","email":"tbrk722@naver.com","mobile":"010-4635-2339","mobile_e164":"+821046352339"}}

                Map<String, Object> resObj = new JSONParser(res.toString()).parseObject();
                Map<String, Object> responseMap = (Map<String, Object>) resObj.get("response");
                log.debug("### email = " + responseMap.get("email"));
                model.addAttribute("id", responseMap.get("id"));
                model.addAttribute("email", responseMap.get("email"));
                model.addAttribute("mobile", responseMap.get("mobile"));
            } else {
                log.error("### 네이버 사용자 프로필 정보 조회 실패!");
            }
        } catch (Exception e) {
            log.error("### Error = "+e);
        }

        return "profile";
    }

    @GetMapping("delete")
    public String delete(HttpSession session, Model model, HttpServletRequest request) {
        String access_token = (String) session.getAttribute("access_token");

        String apiURL;
        apiURL = "https://nid.naver.com/oauth2.0/token";
        apiURL += "?grant_type=delete";
        apiURL += "&client_id=" + CLIENT_ID;
        apiURL += "&client_secret=" + CLIENT_SECRET;
        apiURL += "&access_token=" + access_token;
        apiURL += "&service_provider=NAVER";

        try {
            URL url = new URL(apiURL);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            int responseCode = con.getResponseCode();
            BufferedReader br;
            log.info("### ResponseCode = " + responseCode);
            if (responseCode == 200) { // 정상 호출
                br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            } else {  // 에러 발생
                br = new BufferedReader(new InputStreamReader(con.getErrorStream()));
            }

            String inputLine;
            StringBuffer res = new StringBuffer();
            while ((inputLine = br.readLine()) != null) {
                res.append(inputLine);
            }
            br.close();
            if (responseCode == 200) {
                log.info("### Res = " + res.toString());
            } else {
                log.error("### 네이버 로그인 접근 토큰 삭제 요청 실패!");
            }
        } catch (Exception e) {
            log.error("### Error = "+e);
        }
        return "login";
    }
}