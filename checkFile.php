<?php
//调用
//var_dump($_FILES);exit;
$image = check_illegal($_FILES['file'],'world');
var_dump($image);exit;

/**
 * # 检测文件是否含有木马
 * @param Array $file 文件信息
 * @param string $file_type 文件类型: 默认 image; image->图片(jpg/png/gif) excel->表格(xls/xlsx) world->文档(doc/txt) video->媒体（mp4/mp3）
 * @return Array
 */
function check_illegal($file,$file_type='image')
{
    $ext='';
    //检测文件名是否符合要求
    //excel
    if($file_type == 'excel'){
        if($file['type']){
            $file_array = explode ( ".", $file["name"] );
            $file_extension = strtolower ( array_pop ( $file_array ) );
            switch ($file_extension) {
                case "xls" :
                    // 2003 excel
                    $fh = fopen ( $file ["tmp_name"], "rb" );
                    $bin = fread ( $fh, 8 );
                    fclose ( $fh );
                    $strinfo = @unpack ( "C8chars", $bin );
                    $typecode = "";
                    foreach ( $strinfo as $num ) {
                        $typecode .= dechex ( $num );
                    }
                    if ($typecode == "d0cf11e0a1b11ae1") {
                        $ext = '2003';
                    }
                    break;
                case "xlsx" :
                    // 2007 excel
                    $fh = fopen ( $file ["tmp_name"], "rb" );
                    $bin = fread ( $fh, 4 );
                    fclose ( $fh );
                    $strinfo = @unpack ( "C4chars", $bin );
                    $typecode = "";
                    foreach ( $strinfo as $num ) {
                        $typecode .= dechex ( $num );
                    }
                    if ($typecode == "504b34") {
                        $ext = '2007';
                    }
                    break;
            }
            if($ext == ''){
                return array('success'=>false,'msg'=>'文件后缀名不符合,请上传xls/xlsx后缀的文件');
            }
        }else{
            return array('success'=>false,'msg'=>'未检测到文件后缀');
        }

    }
    //world/txt
    else if($file_type=='world'){
        if($file['type']){
            switch($file['type']){
                case 'application/msword':
                    $ext = 'doc';
                    break;
                case 'text/plain':
                    $ext = 'txt';
                    break;
                default:
                    $ext = '';
                    break;
            }
            if($ext == ''){
                return array('success'=>false,'msg'=>'文件后缀名不符合,请上传doc/txt后缀的文件');
            }
        }else{
            return array('success'=>false,'msg'=>'未检测到文件后缀');
        }

    }
    //image
    else if($file_type == 'image'){
        if ($file['type']) {
            switch($file['type']){
                case 'image/jpeg':
                    $ext = 'jpg';
                    break;
                case 'image/gif':
                    $ext = 'gif';
                    break;
                case 'image/png':
                    $ext = 'png';
                    break;
//                case 'image/tiff':
//                    $ext = 'tif';
//                    break;
                default:
                    $ext = '';
                    break;

            }
            if ($ext==''){
                return array('success'=>false,'msg'=>'图片后缀名不符合,请上传jpg/gif/png后缀的图片');
            }
        }else{
            return array('success'=>false,'msg'=>'未检测到图片后缀');
        }
    }
    //媒体
    else if($file_type == 'video'){
        if ($file['type']) {
            switch($file['type']){
                case 'video/mp4':
                    $ext = 'mp4';
                    break;
                case 'audio/x-m4a':
                    $ext = 'mp3';
                    break;
                case 'video/mpeg':
                    $ext = 'mp3/mp4';
                    break;
                case 'audio/x-ms-wma':
                    $ext = 'mp3/mp4';
                    break;
                default:
                    $ext = '';
                    break;

            }
            if ($ext==''){
                return array('success'=>false,'msg'=>'文件后缀名不符合,请上传mp4/mp3/mpeg/wma后缀的媒体');
            }
        }else{
            return array('success'=>false,'msg'=>'未检测到文件后缀');
        }
    }
    else{
        return array('success'=>false,'msg'=>'请指定上传文件的类型,image/excel/world/video');
    }
    if($file['size'] == 0){
        return array('success'=>false,'msg'=>'该文件为空，请重新上传');
    }
    //检测文件是否存在木马
    if (file_exists($file['tmp_name'])) {
        //打开一个文件或 URL
        $resource = fopen($file['tmp_name'], 'rb');
        //返回指定文件的大小
        $fileSize = filesize($file['tmp_name']);
        //该函数把文件指针从当前位置向前或向后移动到新的位置，新位置从文件头开始以字节数度量。如果成功该函数返回 0，如果失败则返回 -1
        fseek($resource, 0);
        if ($fileSize > 512) { // 取头和尾
            //fread 读取打开的文件 函数会在到达指定长度或读到文件末尾（EOF）时（以先到者为准），停止运行。该函数返回读取的字符串
            //bin2hex 函数把 ASCII 字符的字符串转换为十六进制值
            $hexCode = bin2hex(fread($resource, 512));
            fseek($resource, $fileSize - 512);
            $hexCode .= bin2hex(fread($resource, 512));
        } else { // 取全部
            $hexCode = bin2hex(fread($resource, $fileSize));
        }
        fclose($resource);
        //通过匹配十六进制代码检测是否存在木马脚本
        if (preg_match("/(3c25.*?28.*?29.*?253e)|(3c3f.*?28.*?29.*?3f3e)|(3C534352495054)|(2F5343524950543E)|(3C736372697074)|(2F7363726970743E)/is", $hexCode)) {
            return array('success'=>false,'msg'=>'文件不安全，可能存在木马脚本');
        }else{
            return array('success'=>true,'msg'=>$ext);
        }
    }else{
        return array('success'=>false,'msg'=>'未检测到文件信息');
    }
}



?>