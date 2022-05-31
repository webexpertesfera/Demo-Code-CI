<?php
use Restserver\Libraries\REST_Controller;
//use \Firebase\JWT\JWT;
defined('BASEPATH') OR exit('No direct script access allowed');

require(APPPATH.'/libraries/REST_Controller.php');
require(APPPATH.'/libraries/Format.php');

class Api extends REST_Controller {

    private $siteURL;
    private $qrCodeSecret;
    private $homeDir;
    private $locationDiameter;
    private $googleApiKey;

    public function __construct() {       
        parent::__construct();
        $this->load->model('api_model');
        $this->siteURL = 'site_url'; // website url here e.g. https://example.com/
        $this->qrCodeSecret = 'qr_code_secret'; // secret code for QR Code
        $this->homeDir = 'home_directory'; // website home directory e.g. /home/directory/
        $this->locationDiameter = 60;
        $this->googleApiKey = 'google_api_key'; // google API key
    }

    /*
     * Encryption
     */

    private function json_encode_cbc($data){
        $enc_data=encrypt_cbc(json_encode($data));
        return array('data'=>$enc_data);
    } 

    /*
     * Send Response
     */

    private function _send_response($status,$mess='',$data=[]){
      if(!$status)
      {
        $data = new stdClass();
      }
        $this->response( $this->json_encode_cbc([
                'status' => $status,
                'message' => $mess,
                'data'=>$data
            ])
        ,REST_Controller::HTTP_OK);
    }

    /*
     * Send Response for Priodical Job Details
     */

    private function _send_priodical_response($status,$mess,$data,$priodicalData){
        $this->response( $this->json_encode_cbc([
                'status' => $status,
                'message' => $mess,
                'data'=>$data,
                'priodical_data'=>$priodicalData
            ])
        ,REST_Controller::HTTP_OK);
    }

    /*
     * Send Response With Pagination Data
     */

    private function _send_response_with_pagination($response = array()){
        $this->response( $this->json_encode_cbc($response)
        ,REST_Controller::HTTP_OK);
    }

    /*
     * Worker Login
     */
  
    public function login_post(){
          $postData=jsonToArray(file_get_contents("php://input"));
          $requiredData['company_name'] = isset($postData['company_name']) ? $this->security->xss_clean($postData['company_name']) : '';
          $requiredData['email'] = isset($postData['email']) ? $this->security->xss_clean($postData['email']) : '';
          $requiredData['password'] = isset($postData['password']) ? $this->security->xss_clean($postData['password']) : '';
          $requiredData['device_id'] = isset($postData['device_id']) ? $this->security->xss_clean($postData['device_id']) : '';
          $requiredData['device_type'] = isset($postData['device_type']) ? $this->security->xss_clean($postData['device_type']) : '';
          $requiredData['device_token'] = isset($postData['device_token']) ? $this->security->xss_clean($postData['device_token']) : '';
      
          foreach ($requiredData as $key => $val) {
              if (trim($val) == '') {
                  $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                  $this->_send_response(FALSE,$message); 
                  exit();
              }
          }

          $companyData = $this->api_model->getRowData('ace_register',array('company'=>$requiredData['company_name'],'app_user >'=>0),'id','cbscom',array('id,status'));
          if(! $companyData)
          {
            $this->_send_response(FALSE,'Invalid company name!'); 
            exit();
          }

          if(!$companyData->status)
          {
            $this->_send_response(FALSE,'Access denied. Please contact your company!'); 
            exit();
          }

          $subscriptionData = $this->api_model->getRowData('ace_subscrib_list',array('uid'=>$companyData->id,'module_id'=>6,'status'=>'1','expire_date >'=>date('Y-m-d')),'sbid','cbscom',array('sbid'));
          if(!$subscriptionData)
          {
            $this->_send_response(FALSE,'Access denied. Please contact your company!'); 
            exit();
          }

          $requiredData['company_id'] = $companyData->id;

          $deviceTypes = array('ios','android');
          if(!in_array($requiredData['device_type'], $deviceTypes))
          {
            $this->_send_response(FALSE,'Invalid device type!'); 
            exit();
          }

          $requiredData['type'] = isset($postData['type']) ? $this->security->xss_clean($postData['type']) : '';
          
          $result = $this->api_model->login($requiredData);
          if($result['status'])
          {
            $result['user_data']['expire_at'] = $this->expirydate();
            $result['user_data']['expire_at'] = $this->expirydate();
            $token = jwt::encode($result['user_data'],TOKEN_SECRET_KEY);
            $data = new stdClass();
            $data->token = $token;
            $this->_send_response($result['status'],$result['message'],$data);
          }
          else
          {
            $this->_send_response($result['status'],$result['message']);
          } 
    }

    /*
     * Forgot Password
     */

    public function forgotPassword_post(){
        $postData=jsonToArray(file_get_contents("php://input"));
        $requiredData['email'] = isset($postData['email']) ? $this->security->xss_clean($postData['email']) : '';
        $requiredData['company_name'] = isset($postData['company_name']) ? $this->security->xss_clean($postData['company_name']) : '';
        
        foreach ($requiredData as $key => $val) {
            if (trim($val) == '') {
                $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                $this->_send_response(FALSE,$message); 
                exit();
            }
        }

        $companyData = $this->api_model->getRowData('ace_register',array('company'=>$requiredData['company_name'],'app_user >'=>0),'id','cbscom',array('id'));
        if(! $companyData)
        {
          $this->_send_response(FALSE,'Invalid company name!'); 
          exit();
        }
        
        $userData = $this->api_model->getRowData('ace_workerstbl',array('emailid'=>$requiredData['email'],'company_id'=>$companyData->id),'workerid','default',array('workerid'));
        if(! $userData)
        {
          $this->_send_response(FALSE,"Invalid Email or company name!"); 
          exit();
        }

        $insert = array();
        // $insert['code'] = rand(pow(10, 3), pow(10, 4)-1);
        $insert['code'] = 1234;
        $insert['email'] = $requiredData['email'];
        $insert['company_id'] = $companyData->id;
        $insert['created_at'] = date('Y-m-d H:i:s');
        $insert['updated_at'] = date('Y-m-d H:i:s');

        $result = $this->api_model->insert('ace_verification_code',$insert);
        if(! $result)
        {
          $this->_send_response(FALSE,"Internal server error!"); 
          exit();
        }

         $emailData['email'] = $requiredData['email'];   
         $emailData['code'] = $insert['code'];   
         $emailData['subject'] = 'Forgot Password';   
         $emailData['template'] = 'forgotPassword'; 
         //$status = sendMail($emailData);
         $status = true;

         if($status)
         {
            $this->_send_response(TRUE,"we have sent you a 4-digit code on your email address."); 
         }
         else
         {
            $this->_send_response(FALSE,"Error in sending email!");
         }
    }

    /*
     * OTP Verification
     */

    public function otpVerify_post(){
        $postData=jsonToArray(file_get_contents("php://input"));
        $requiredData['email'] = isset($postData['email']) ? $this->security->xss_clean($postData['email']) : '';
        $requiredData['company_name'] = isset($postData['company_name']) ? $this->security->xss_clean($postData['company_name']) : '';
        $requiredData['verification_code'] = isset($postData['verification_code']) ? $this->security->xss_clean($postData['verification_code']) : '';
        
        foreach ($requiredData as $key => $val) {
            if (trim($val) == '') {
                $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                $this->_send_response(FALSE,$message); 
                exit();
            }
        }

        $companyData = $this->api_model->getRowData('ace_register',array('company'=>$requiredData['company_name'],'app_user >'=>0),'id','cbscom',array('id'));
        if(! $companyData)
        {
          $this->_send_response(FALSE,'Invalid company name!'); 
          exit();
        }
        
        $verificationData = $this->api_model->getRowData('ace_verification_code',array('email'=>$requiredData['email'],'company_id'=>$companyData->id,'code'=>$requiredData['verification_code'],'is_verified'=>'0'));
        if(! $verificationData)
        {
          $this->_send_response(FALSE,"Invalid verification_code!"); 
          exit();
        }

        $currentTime = date("Y-m-d H:i:s");
        $expireTime = date('Y-m-d H:i:s',strtotime('+0 hour +15 minutes',strtotime($verificationData->created_at)));

        if($currentTime > $expireTime)
        {
            $this->_send_response(FALSE,"verification code expired!"); 
            exit();
        }

        $data = new stdClass();
        $data->email = $requiredData['email'];
        $data->company_name = $requiredData['company_name'];
        $data->verification_code = $requiredData['verification_code'];

        $this->_send_response(TRUE,"Otp Verified successfully!",$data); 
        exit();
    }

    /*
     * Reset Password
     */

    public function resetPassword_post(){
        $postData=jsonToArray(file_get_contents("php://input"));
        $requiredData['email'] = isset($postData['email']) ? $this->security->xss_clean($postData['email']) : '';
        $requiredData['company_name'] = isset($postData['company_name']) ? $this->security->xss_clean($postData['company_name']) : '';
        $requiredData['verification_code'] = isset($postData['verification_code']) ? $this->security->xss_clean($postData['verification_code']) : '';
        $requiredData['new_password'] = isset($postData['new_password']) ? $this->security->xss_clean($postData['new_password']) : '';
        
        foreach ($requiredData as $key => $val) {
            if (trim($val) == '') {
                $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                $this->_send_response(FALSE,$message); 
                exit();
            }
        }

        $companyData = $this->api_model->getRowData('ace_register',array('company'=>$requiredData['company_name'],'app_user >'=>0),'id','cbscom',array('id'));
        if(! $companyData)
        {
          $this->_send_response(FALSE,'Invalid company name!'); 
          exit();
        }
        
        $verificationData = $this->api_model->getRowData('ace_verification_code',array('email'=>$requiredData['email'],'company_id'=>$companyData->id,'code'=>$requiredData['verification_code'],'is_verified'=>'0'));
        if(! $verificationData)
        {
          $this->_send_response(FALSE,"Invalid data!"); 
          exit();
        }

        if(strlen(trim($requiredData['new_password'])) < 4 || strlen(trim($requiredData['new_password'])) > 16)
        {
            $this->_send_response(FALSE,"Your password must be between 3 and 17 characters"); 
            exit();
        }

        $result = $this->api_model->updatePassword($verificationData->id,$requiredData['email'],$companyData->id,$requiredData['new_password']);
        if($result)
        {
          $this->_send_response(TRUE,"Password reset successfully!");
        }
        else
        {
          $this->_send_response(FALSE,"Internal server error!"); 
        }
    }

    /*
     * Change Password from Profile page
     */

    public function changePassword_post(){
        $postData=jsonToArray(file_get_contents("php://input"));
        $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
        $requiredData['old_password'] = isset($postData['old_password']) ? $this->security->xss_clean($postData['old_password']) : '';
        $requiredData['new_password'] = isset($postData['new_password']) ? $this->security->xss_clean($postData['new_password']) : '';
        
        foreach ($requiredData as $key => $val) {
            if (trim($val) == '') {
                $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                $this->_send_response(FALSE,$message); 
                exit();
            }
        }

        $userData = $this->getUserData($requiredData['token']);

        $workerData = $this->api_model->getRowData('ace_workerstbl',array('workerid'=>$userData->worker_id),'workerid','default',array('password'));
        if(!$workerData)
        {
          $this->_send_response(FALSE,"Invalid user"); 
          exit();
        }

        if($workerData->password != $requiredData['old_password'])
        {
          $this->_send_response(FALSE,"Invalid Old Password"); 
          exit();
        }

        if(strlen(trim($requiredData['new_password'])) < 4 || strlen(trim($requiredData['new_password'])) > 16)
        {
            $this->_send_response(FALSE,"Your password must be between 3 and 17 characters"); 
            exit();
        }

        $result = $this->api_model->changePassword($userData->worker_id,$requiredData['new_password']);
        if($result)
        {
          $this->_send_response(TRUE,"Password changed successfully!");
        }
        else
        {
          $this->_send_response(FALSE,"Internal server error!"); 
        }
    }

    /*
     * Get Profile Data
     */

    public function getProfile_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $workerData = $this->api_model->getRowData('ace_workerstbl',array('workerid'=>$userData->worker_id,'company_id'=>$userData->company_id),'workerid','default',array('firstname','lastname','emailid','contactno','image'));
           if(!$workerData)
           {
             $this->_send_response(FALSE,'Internal server error'); 
             exit();
           }

           if($workerData->image)
            $workerData->image = $this->siteURL.'cleaners-images/'.$workerData->image;

            $this->_send_response(TRUE,'Profile Data',$workerData); 
            exit();
    }

    /*
     * Add Feedback on Complaint
     */

    public function addComplaintFeedback_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['complaint_id'] = isset($postData['complaint_id']) ? $this->security->xss_clean($postData['complaint_id']) : '';
            $requiredData['subject'] = isset($postData['subject']) ? $this->security->xss_clean($postData['subject']) : '';
            $requiredData['message'] = isset($postData['message']) ? $this->security->xss_clean($postData['message']) : '';
            $requiredData['status'] = isset($postData['status']) ? $this->security->xss_clean($postData['status']) : '';
            $requiredData['date'] = isset($postData['date']) ? $this->security->xss_clean($postData['date']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $complaintData = $this->api_model->getComplaintData($requiredData['complaint_id']);
           if(!$complaintData)
           {
             $this->_send_response(FALSE,'Invalid Complaint id'); 
             exit();
           }

           if($complaintData->status == 'closed')
           {
             $this->_send_response(FALSE,'This complaint has been closed'); 
             exit();
           }

           $insert = array();
           $insert['company_id'] = $complaintData->company_id;
           $insert['company_admin'] = $complaintData->company_admin;
           $insert['company_user'] = $complaintData->company_user;
           $insert['createby'] = 'worker';
           $insert['createbyid'] = $userData->worker_id;
           $insert['complaintautoid'] = $complaintData->compid;
           $insert['cont_id'] = $complaintData->cont_id;
           $insert['aud_id'] = $complaintData->aud_id;
           $insert['customerid'] = $complaintData->customerid;
           $insert['auditby'] = $complaintData->auditby;
           $insert['cleaner'] = $complaintData->cleaner;
           $insert['aud_date'] = $complaintData->aud_date;
           $insert['subject'] = $requiredData['subject'];
           $insert['message'] = $requiredData['message'];
           $insert['complaintid'] = $complaintData->complaintid;
           $insert['per_resp'] = $complaintData->per_resp;
           $insert['complaint_date'] = $complaintData->complaint_date;
           $insert['complete_date'] = $requiredData['date'];
           $insert['datetime'] = date('Y-m-d H:i:s');
           $insert['status'] = $requiredData['status'];
           
           $images = array();
           if(isset($postData['first_image']) && trim($postData['first_image']) != '')
           {
             $firstImage = $this->security->xss_clean($postData['first_image']);
             $imageName = $this->saveImage($firstImage,'complaint-images');
             array_push($images, $imageName);
           }

           if(isset($postData['second_image']) && trim($postData['second_image']) != '')
           {
             $secondImage = $this->security->xss_clean($postData['second_image']);
             $imageName = $this->saveImage($secondImage,'complaint-images');
             array_push($images, $imageName);
           }

           if(sizeof($images) > 0)
           {
             $insert['image'] = implode(",",$images);
           }

           $insertData = $this->api_model->addComplaintFeedback($insert);
           if($insertData)
           {
             $this->_send_response(TRUE,'feedback added successfully',new stdClass());
           }
           else
           {
             $this->_send_response(FALSE,'Internal server error');
           }
           exit();
    }

    /*
     * Save Image from Base64 String
     */

    private function saveImage($image_string,$folder_name){
      $image_base64 = base64_decode($image_string, TRUE);
      if(!$image_base64)
      {
        $this->_send_response(FALSE,'Invalid image data');
        exit();
      }
      $f = finfo_open();
      $mime_type = finfo_buffer($f, $image_base64, FILEINFO_MIME_TYPE);
      finfo_close($f);
      $imageName = uniqid().".".substr($mime_type,6);
      $status = file_put_contents($this->homeDir.$folder_name.'/'.$imageName,$image_base64);
      if(!$status)
      {
        $this->_send_response(FALSE,'Internal server error');
        exit();
      }
      return $imageName;
    }

    /*
     * Add Feedback on Priodical Jobs
     */

    public function addPriodicalJobFeedback_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['status_id'] = isset($postData['status_id']) ? $this->security->xss_clean($postData['status_id']) : '';
            $requiredData['message'] = isset($postData['message']) ? $this->security->xss_clean($postData['message']) : '';
            $requiredData['status'] = isset($postData['status']) ? $this->security->xss_clean($postData['status']) : '';
            $requiredData['date'] = isset($postData['date']) ? $this->security->xss_clean($postData['date']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $status = array(0,1);
           if(!in_array($requiredData['status'], $status))
           {
             $this->_send_response(FALSE,'Invalid status value'); 
             exit();
           }

           $priodicalData = $this->api_model->getPriodicalStatusData($requiredData['status_id']);
           if(!$priodicalData)
           {
             $this->_send_response(FALSE,'Invalid Status id'); 
             exit();
           }

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['cont_id'] = $priodicalData->cont_id;
           $insert['periodic_id'] = $priodicalData->periodic_id;
           $insert['freq_times'] = $priodicalData->freq_times;

           $update = array();
           $update['comments'] = $requiredData['message'];
           $update['date'] = $requiredData['date'];
           $update['status'] = $requiredData['status'];
           
           $images = array();
           if(isset($postData['first_image']) && trim($postData['first_image']) != '')
           {
             $firstImage = $this->security->xss_clean($postData['first_image']);
             $imageName = $this->saveImage($firstImage,'periodicals');
             array_push($images, $imageName);
           }

           if(isset($postData['second_image']) && trim($postData['second_image']) != '')
           {
             $secondImage = $this->security->xss_clean($postData['second_image']);
             $imageName = $this->saveImage($secondImage,'periodicals');
             array_push($images, $imageName);
           }

           $updateData = $this->api_model->updatePriodicalData($requiredData['status_id'],$update,$insert,$images);
           if($updateData)
           {
             $this->_send_response(TRUE,'feedback added successfully',new stdClass());
           }
           else
           {
             $this->_send_response(FALSE,'Internal server error');
           }
           exit();
    }

    /*
     * Add Feedback on Follow Up
     */

    public function addFollowUpFeedback_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['follow_up_id'] = isset($postData['follow_up_id']) ? $this->security->xss_clean($postData['follow_up_id']) : '';
            $requiredData['message'] = isset($postData['message']) ? $this->security->xss_clean($postData['message']) : '';
            $requiredData['status'] = isset($postData['status']) ? $this->security->xss_clean($postData['status']) : '';
            $requiredData['date'] = isset($postData['date']) ? $this->security->xss_clean($postData['date']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $followData = $this->api_model->getFollowUpData($requiredData['follow_up_id'],array('fid'));
           if(!$followData)
           {
             $this->_send_response(FALSE,'Invalid Follow up id'); 
             exit();
           }

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['follow_up_id'] = $requiredData['follow_up_id'];
           $insert['last_upd_by'] = $userData->worker_id;
           $insert['emp_id'] = $userData->worker_id;

           $update = array();
           $update['comment'] = $requiredData['message'];
           $update['complete_date'] = $requiredData['date'];
           $update['status'] = $requiredData['status'];
           $update['response_status'] = '1';
           
           $images = array();
           if(isset($postData['first_image']) && trim($postData['first_image']) != '')
           {
             $firstImage = $this->security->xss_clean($postData['first_image']);
             $imageName = $this->saveImage($firstImage,'followup-images');
             array_push($images, $imageName);
           }

           if(isset($postData['second_image']) && trim($postData['second_image']) != '')
           {
             $secondImage = $this->security->xss_clean($postData['second_image']);
             $imageName = $this->saveImage($secondImage,'followup-images');
             array_push($images, $imageName);
           }

           $updateData = $this->api_model->updateFollowData($update,$insert,$images);
           if($updateData)
           {
             $this->_send_response(TRUE,'feedback added successfully',new stdClass());
           }
           else
           {
             $this->_send_response(FALSE,'Internal server error');
           }
           exit();
    }

    /*
     * Add Feedback on Audit
     */

    public function addAuditFeedback_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['audit_id'] = isset($postData['audit_id']) ? $this->security->xss_clean($postData['audit_id']) : '';
            $requiredData['cleaningarea_id'] = isset($postData['cleaningarea_id']) ? $this->security->xss_clean($postData['cleaningarea_id']) : '';
            $requiredData['message'] = isset($postData['message']) ? $this->security->xss_clean($postData['message']) : '';
            $requiredData['status'] = isset($postData['status']) ? $this->security->xss_clean($postData['status']) : '';
            $requiredData['date'] = isset($postData['date']) ? $this->security->xss_clean($postData['date']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $auditData = $this->api_model->getAuditData($userData->worker_id,$userData->company_id,$requiredData['audit_id']);
           if(!$auditData)
           {
             $this->_send_response(FALSE,'Invalid Audit id'); 
             exit();
           }

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['cont_id'] = $auditData->cont_id;
           $insert['aud_id'] = $requiredData['audit_id'];
           $insert['carea'] = $requiredData['cleaningarea_id'];
           $insert['last_upd_by'] = $userData->worker_id;

           $update = array();
           $update['comt'] = $requiredData['message'];
           $update['complete_date'] = $requiredData['date'];
           $update['status'] = $requiredData['status'];
           
           $images = array();
           if(isset($postData['first_image']) && trim($postData['first_image']) != '')
           {
             $firstImage = $this->security->xss_clean($postData['first_image']);
             $imageName = $this->saveImage($firstImage,'uploadmultiple');
             array_push($images, $imageName);
           }

           if(isset($postData['second_image']) && trim($postData['second_image']) != '')
           {
             $secondImage = $this->security->xss_clean($postData['second_image']);
             $imageName = $this->saveImage($secondImage,'uploadmultiple');
             array_push($images, $imageName);
           }

           $updateData = $this->api_model->updateAuditData($update,$insert,$images,$requiredData['audit_id']);
           if($updateData)
           {
             $this->_send_response(TRUE,'feedback added successfully',new stdClass());
           }
           else
           {
             $this->_send_response(FALSE,'Internal server error');
           }
           exit();
    }

   
