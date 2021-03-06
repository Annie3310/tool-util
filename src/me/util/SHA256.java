package me.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA256 工具类
 * @author WangJ
 */
public class SHA256 {
    /**
     * 传入文本内容，返回 SHA-256 串
     *
     * @param strText
     * @return
     */
    public static String SHA256(final String strText)
    {
        return SHA(strText);
    }

    /**
     * 字符串SHA256加密
     * @param strText
     * @return
     */
    private static String SHA(final String strText)
    {
        // 返回值
        String strResult = null;

        // 是否是有效字符串
        if (strText != null && strText.length() > 0)
        {
            try
            {
                // SHA 加密开始
                // 创建加密对象 并傳入加密類型
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                // 传入要加密的字符串
                messageDigest.update(strText.getBytes());
                // 得到 byte 类型结果
                byte[] byteBuffer = messageDigest.digest();

                // 将 byte 转换为 string
                StringBuffer strHexString = new StringBuffer();
                // 遍历 byte buffer
                for (int i = 0; i < byteBuffer.length; i++)
                {
                    String hex = Integer.toHexString(0xff & byteBuffer[i]);
                    if (hex.length() == 1)
                    {
                        strHexString.append('0');
                    }
                    strHexString.append(hex);
                }
                // 得到返回结果
                strResult = strHexString.toString();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
        }

        return strResult;
    }
}
