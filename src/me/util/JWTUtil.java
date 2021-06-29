package me.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 使用时需要在 pom.xml 中引入
 * <dependency>
 *             <groupId>com.auth0</groupId>
 *             <artifactId>java-jwt</artifactId>
 *             <version>3.15.0</version>
 * </dependency>
 */
public class JWTUtil {
    /**
     * 过期时间
     */
    private static final long EXPIRE_TIME = 120 * 60 * 1000;
    /**
     * token私钥
     * 随便写
     */
    private static final String TOKEN_SECRET = "a75341ffa361e1520ba1f70904114364e0d94cc43755297cf1630e26147d7a0a";

    /**
     * 生成token
     *
     * @param aName 用户ID
     * @return token
     */
    public static String getToken(String aName) {
        Date expireTime = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        Map<String, Object> header = new HashMap<>(2);
        header.put("Type", "Jwt");
        header.put("alg", "HS256");

        return JWT.create()
                .withHeader(header)
                .withClaim("aName", aName)
                .withExpiresAt(expireTime)
                .sign(algorithm);
    }

    /**
     * 验证token
     *
     * @param token token
     * @return token中包含的用户id
     */
    public static String verifyToken(String token) {
        try{
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier jwtVerifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            String id = String.valueOf(decodedJWT.getClaim("aName"));
            return id;
        }catch (Exception e){
            return null;
        }
    }

    public static String test(String token) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(token);
        return (decodedJWT.toString());
    }
}
