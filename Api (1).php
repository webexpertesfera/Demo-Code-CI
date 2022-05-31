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

    /*
     * Contact Us
     */

    public function contactUs_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['name'] = isset($postData['name']) ? $this->security->xss_clean($postData['name']) : '';
            $requiredData['subject'] = isset($postData['subject']) ? $this->security->xss_clean($postData['subject']) : '';
            $requiredData['message'] = isset($postData['message']) ? $this->security->xss_clean($postData['message']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

            if(strlen(trim($requiredData['subject'])) < 4 || strlen(trim($requiredData['subject'])) > 75)
            {
                $this->_send_response(FALSE,"Subject must be between 4 and 75 characters"); 
                exit();
            }

            if(strlen(trim($requiredData['message'])) < 10 || strlen(trim($requiredData['message'])) > 255)
            {
                $this->_send_response(FALSE,"Message must be between 10 and 255 characters"); 
                exit();
            }
           $workerData = $this->api_model->getRowData('ace_workerstbl',array('workerid'=>$userData->worker_id,'company_id'=>$userData->company_id),'workerid','default',array('emailid','contactno'));
           if(!$workerData)
           {
             $this->_send_response(FALSE,'Internal server error'); 
             exit();
           }

            $companyData = $this->api_model->getRowData('ace_register',array('id'=>$userData->company_id),'id','cbscom',array('email'));
            $requiredData = (Object) $requiredData;
            $this->_send_response(TRUE,'Message sent successfully',$requiredData); 
            exit();
    }

    /*
     * Update Profile Image
     */

    public function updateProfileImage_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['image_string'] = isset($postData['image_string']) ? $this->security->xss_clean($postData['image_string']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $image_base64 = base64_decode($requiredData['image_string'], TRUE);
            if(!$image_base64)
            {
              $this->_send_response(FALSE,'Invalid image');
              exit();
            }
            $f = finfo_open();
            $mime_type = finfo_buffer($f, $image_base64, FILEINFO_MIME_TYPE);
            finfo_close($f);
            $imageName = $userData->worker_id.".".substr($mime_type,6);
            $saveImage = file_put_contents($this->homeDir.'cleaners-images/'.$imageName,$image_base64);
            if($saveImage)
            {
              $update = $this->api_model->updateRowData('ace_workerstbl',array('image'=>$imageName),array('workerid'=>$userData->worker_id));
              if($update)
              {
                $this->_send_response(TRUE,'Image uploaded successfully',new stdClass()); 
                exit();
              }
              else
              {
                $this->_send_response(FALSE,'Internal Server Error'); 
                exit();
              }
            }
            else
            {
              $this->_send_response(FALSE,'Internal Server Error'); 
              exit();
            }
    }

    /*
     * Get List of Work Shedules
     */

    public function getShedules_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $requiredData['filter_by'] = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
            if(isset($postData['filter_by']) && $requiredData['filter_by'] == 'week')
            {
              $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
              $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

            $filterBy = array('day','month','week');
            if(! in_array(strtolower($requiredData['filter_by']), $filterBy))
            {
              $this->_send_response(FALSE,'Invalid value of filter_by !'); 
              exit();
            }

            $search_keyword = '';
            if(isset($postData['search_keyword']))
            {
              $search_keyword = $this->security->xss_clean($postData['search_keyword']);
            }

           $userData = $this->getUserData($requiredData['token']);

           if(!is_numeric($requiredData['page']))
           {
             $this->_send_response(FALSE,'Invalid page'); 
             exit();
           } 

            $page = (int) $requiredData['page'];
            if($page == 0)
            {
              $this->_send_response(FALSE,'Invalid page'); 
              exit();
            } 

           if($requiredData['filter_by'] == 'week')
           {
             $sheduleData = $this->api_model->getShedulesByweek($userData->worker_id,$userData->company_id,$search_keyword,$requiredData['date_from'],$requiredData['date_to'],$page);
           }
           else
           {
             if(isset($postData['filter_value']))
             $sheduleData = $this->api_model->getShedules($userData->worker_id,$userData->company_id,$search_keyword,$requiredData['filter_by'],$this->security->xss_clean($postData['filter_value']),$page);
             else
             $sheduleData = $this->api_model->getShedules($userData->worker_id,$userData->company_id,$search_keyword,$requiredData['filter_by'],$page);
           }
           
           $this->_send_response_with_pagination($sheduleData);
    }

    /*
     * Work Shedule Details (Old)
     */

    // public function workSheduleDetail_post(){
    //         $postData=jsonToArray(file_get_contents("php://input"));
    //         $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
    //         $requiredData['cont_id'] = isset($postData['cont_id']) ? $this->security->xss_clean($postData['cont_id']) : '';
            
    //         foreach ($requiredData as $key => $val) {
    //             if (trim($val) == '') {
    //                 $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
    //                 $this->_send_response(FALSE,$message); 
    //                 exit();
    //             }
    //         }

    //        $userData = $this->getUserData($requiredData['token']);

    //        $sheduleData = $this->api_model->getSheduleDetail($userData->worker_id,$userData->company_id,$requiredData['cont_id']);
    //        if(! $sheduleData)
    //        {
    //           $this->_send_response(FALSE,'Invalid Contract id!'); 
    //           exit();
    //        }

    //        $sheduleData->service = $this->api_model->getColumnValue('ace_services','sid',array('sid'=>$sheduleData->service),'service_name');
    //        $sheduleData->cleaningarea = $this->api_model->getColumnValue('ace_cleanarea','cid',array('cid'=>$sheduleData->cleaningarea),'clnarea');

    //        $shedule_data = new stdClass();
    //        $shedule_data->cont_id = $sheduleData->cont_id;
    //        $shedule_data->identifier = $sheduleData->identifier;
    //        $shedule_data->date = $sheduleData->fdate;
    //        $shedule_data->entry_time = $sheduleData->cleaningtime;
    //        $shedule_data->companyname = $sheduleData->companyname;
    //        $shedule_data->client_firstname = $sheduleData->firstname;
    //        $shedule_data->client_lastname = $sheduleData->lastname;
    //        $shedule_data->address = $sheduleData->address;
    //        $shedule_data->service = $sheduleData->service;
    //        $shedule_data->cleaningarea = $sheduleData->cleaningarea;
    //        $shedule_data->latitude = $sheduleData->latitude;
    //        $shedule_data->longitude = $sheduleData->longitude;

    //        $weekDays = array('sun','mon','tue','wed','thu','fri','sat');
    //        $workDaysArray = array();
    //        foreach($weekDays as $weekDay)
    //        {
    //          if($sheduleData->$weekDay)
    //          {
    //            array_push($workDaysArray, $weekDay);
    //          }
    //        }

    //        $shedule_data->work_days = implode(", ",$workDaysArray);
    //        $shedule_data->days_per_week = sizeof($workDaysArray);

    //        if(!$sheduleData->is_read)
    //        {
    //          $updateRead = $this->api_model->updateRead('ace_contract',array('cid'=>$requiredData['cont_id']));
    //        }
           
    //        $this->_send_response(TRUE,"Sheduled Data",$shedule_data);
    // }

    /*
     * Work Shedule Details
     */

    public function workSheduleDetail_post()
    {
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['cont_id'] = isset($postData['cont_id']) ? $this->security->xss_clean($postData['cont_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $sheduleData = $this->api_model->allSeduleDetails($userData->worker_id,$userData->company_id,$requiredData['cont_id']);
           if(! $sheduleData)
           {
              $this->_send_response(FALSE,'Invalid Contract id!'); 
              exit();
           }

           $responseData = new stdClass();
           $cliningAreaIds = array();
           $weekDays = array('sun','mon','tue','wed','thu','fri','sat');
           $cleaningarea = array();
           $is_read = 1;
           foreach($sheduleData as $shedule)
           {
             $responseData->cont_id = $shedule->cont_id;
             $responseData->contract_id = $shedule->contract_id;
             $responseData->identifier = $shedule->identifier;
             $responseData->date = $shedule->fdate;
             $responseData->end_date = $shedule->end_date;
             $responseData->cleaningtime = $shedule->cleaningtime;
             $responseData->companyname = $shedule->companyname;
             $responseData->client_firstname = $shedule->firstname;
             $responseData->client_lastname = $shedule->lastname;
             $responseData->address = $shedule->address;
             $responseData->city = $shedule->city;
             $responseData->state = $shedule->state;
             $responseData->postcode = $shedule->postcode;
             $responseData->latitude = $shedule->latitude;
             $responseData->longitude = $shedule->longitude;
             $is_read = $shedule->is_read;

             array_push($cliningAreaIds, $shedule->cleaningarea);
           }

           if(sizeof($cliningAreaIds) > 0)
           {
             $cliningAreaIds = array_unique($cliningAreaIds);
             foreach($cliningAreaIds as $key => $cliningAreaId)
             {
               $area = new stdClass();
               $services = array();
               foreach($sheduleData as $shedule)
               {
                 if($shedule->cleaningarea == $cliningAreaId)
                 {
                    $workDaysArray = array();
                    $service = new stdClass();
                    $service->service_name = $shedule->service_name;
                     foreach($weekDays as $weekDay)
                     {
                       if($shedule->$weekDay)
                       {
                         array_push($workDaysArray, $weekDay);
                       }
                     }
                     $service->work_days = implode(", ",$workDaysArray);
                     $service->days_per_week = sizeof($workDaysArray);
                     array_push($services,$service);
                     $area->area_title = $shedule->clnarea;
                 }
               }
               $area->services = $services;
               $area->time = $shedule->whrs;
               $area->total_time = $shedule->twhrs;
               $area->qty = $shedule->qty;
               array_push($cleaningarea, $area);
             }
           }
           $cleaningarea = array_reverse($cleaningarea);
           $responseData->cleaningareas = $cleaningarea;

           if(!$is_read)
           {
             $updateRead = $this->api_model->updateRead('ace_contract',array('cid'=>$requiredData['cont_id']));
           }
           
           $this->_send_response(TRUE,"Sheduled Data",$responseData);
    }

    /*
     * Get List of Follow Ups
     */

    public function followUp_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $filter_by = '';
            if(isset($postData['filter_by'])){
              $filter_by = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
              if($filter_by == 'week')
              {
                $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
                $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
              }
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $searchKeyword = '';
           if(isset($postData['search_keyword']))
           {
             $searchKeyword = $this->security->xss_clean($postData['search_keyword']);
           }

           if(isset($postData['filter_value'])){
              $requiredData['filter_value'] = $this->security->xss_clean($postData['filter_value']);
            }
            else
            {
              $requiredData['filter_value'] = '';
            }

             if(!is_numeric($requiredData['page']))
             {
               $this->_send_response(FALSE,'Invalid page'); 
               exit();
             } 

              $page = (int) $requiredData['page'];
              if($page == 0)
              {
                $this->_send_response(FALSE,'Invalid page'); 
                exit();
              } 

           $followData = $this->api_model->getFollowUpList($userData->worker_id,$userData->company_id,$searchKeyword,$filter_by,$requiredData,$page);
           
           $this->_send_response_with_pagination($followData);
    }

    /*
     * Follow Up Details
     */

    public function followUpDetail_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['follow_up_id'] = isset($postData['follow_up_id']) ? $this->security->xss_clean($postData['follow_up_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $followData = $this->api_model->getFollowUpDetail($userData->worker_id,$userData->company_id,$requiredData['follow_up_id']);
           if(!$followData)
           {
            $this->_send_response(FALSE,'Invalid follow up id'); 
            exit();
           }

           $workerData = $this->api_model->getRowData('ace_workerstbl',array('workerid'=>$userData->worker_id,'company_id'=>$userData->company_id),'workerid','default',array('firstname','lastname'));
           if(!$workerData)
           {
             $followData->cleaner_firstname = '';
             $followData->cleaner_lastname = '';
           }
           else
           {
             $followData->cleaner_firstname = $workerData->firstname;
             $followData->cleaner_lastname = $workerData->lastname;
           }

             $followData->ftype = $this->api_model->getColumnValue('ace_followuptype','ftyid',array('ftyid'=>$followData->ftype),'ftype');
             $customerData = $this->api_model->getRowData('ace_customer',array('customerid'=>$followData->customerid),'customerid','default',array('firstname','lastname','companyname'));
             if($customerData)
             {
               $followData->customer_firstname = $customerData->firstname;
               $followData->customer_lastname = $customerData->lastname;
               $followData->customer_companyname = $customerData->companyname;
             }
             else
             {
               $followData->customer_firstname = '';
               $followData->customer_lastname = '';
               $followData->customer_companyname = '';
             }

             if(!$followData->is_read)
             {
               $updateRead = $this->api_model->updateRead('ace_followup',array('fid'=>$requiredData['follow_up_id']));
             }
           
           $this->_send_response(TRUE,"Sheduled Data",$followData);
    }

    /*
     * Get List of One Off Jobs
     */

    public function oneOffJobList_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $filter_by = '';
            if(isset($postData['filter_by'])){
              $filter_by = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
              if($filter_by == 'week')
              {
                $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
                $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
              }
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $searchKeyword = '';
           $status = '';
           if(isset($postData['search_keyword']))
           {
             $searchKeyword = $this->security->xss_clean($postData['search_keyword']);
           }
           if(isset($postData['status']))
           {
             $status = $this->security->xss_clean($postData['status']);
           }
           if(isset($postData['filter_value'])){
              $requiredData['filter_value'] = $this->security->xss_clean($postData['filter_value']);
            }
            else
            {
              $requiredData['filter_value'] = '';
            }

           if(!is_numeric($requiredData['page']))
           {
             $this->_send_response(FALSE,'Invalid page'); 
             exit();
           } 

            $page = (int) $requiredData['page'];
            if($page == 0)
            {
              $this->_send_response(FALSE,'Invalid page'); 
              exit();
            } 


           $jobData = $this->api_model->getOneOffJobList($userData->worker_id,$userData->company_id,$searchKeyword,$filter_by,$requiredData,$status,$page);
           
           $this->_send_response_with_pagination($jobData);
    }

    /*
     * One Off Job Details
     */

    public function oneOffJobDetails_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['job_id'] = isset($postData['job_id']) ? $this->security->xss_clean($postData['job_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $jobData = $this->api_model->getOneOffJobDetails($userData->worker_id,$userData->company_id,$requiredData['job_id']);
           if($jobData)
           {
             $amount= 0;
             $responseData = new stdClass();
             $responseData->job_id = $jobData->job_id;
             $responseData->date = $jobData->date;
             $responseData->contract_id = $jobData->contract_id;
             $responseData->companyname = $jobData->companyname;
             $responseData->customer_firstname = $jobData->customer_firstname;
             $responseData->customer_lastname = $jobData->customer_lastname;
             $responseData->description = $jobData->description;
             $responseData->status = $jobData->status;
             $responseData->site_address = $jobData->address.', '.$jobData->city.', '.$jobData->state.'-'.$jobData->postcode;
             $responseData->billing_address = $jobData->billing_address.', '.$jobData->billing_city.', '.$jobData->billing_state.'-'.$jobData->billing_zipcode;
             $cleaningarea = $this->api_model->getCleaningArea($userData->company_id,$userData->worker_id,$jobData->job_id);
             if($cleaningarea)
             {
               foreach($cleaningarea as $clean)
               {
                 $amount = $amount + (int) $clean->amount;
               }
             }
             $responseData->amount = $amount;
             $responseData->cleanAreas = $cleaningarea;
             if(!$jobData->is_read)
             {
               $updateRead = $this->api_model->updateRead('ace_oneoffjob',array('jid'=>$requiredData['job_id']));
             }
             $this->_send_response(TRUE,"One Off Job Data",$responseData);
           }
           else
           {
              $this->_send_response(FALSE,'Invalid Job Id!');
           }
    }

    /*
     * Add Feedback on One Off Job
     */

    public function addOneOffJobFeedback_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['onoff_detail_id'] = isset($postData['onoff_detail_id']) ? $this->security->xss_clean($postData['onoff_detail_id']) : '';
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

           $jobData = $this->api_model->getOneOffJobDetailData($requiredData['onoff_detail_id'],array('onid','oneofid'));
           if(!$jobData)
           {
             $this->_send_response(FALSE,'Invalid One off job detail id'); 
             exit();
           }

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['onid'] = $requiredData['onoff_detail_id'];
           $insert['last_upd_by'] = $userData->worker_id;
           $insert['emp_id'] = $userData->worker_id;

           $update = array();
           $update['comment'] = $requiredData['message'];
           $update['complete_date'] = $requiredData['date'];
           $update['status'] = $requiredData['status'];
           
           $images = array();
           if(isset($postData['first_image']) && trim($postData['first_image']) != '')
           {
             $firstImage = $this->security->xss_clean($postData['first_image']);
             $imageName = $this->saveImage($firstImage,'oneoffjob-images');
             array_push($images, $imageName);
           }

           if(isset($postData['second_image']) && trim($postData['second_image']) != '')
           {
             $secondImage = $this->security->xss_clean($postData['second_image']);
             $imageName = $this->saveImage($secondImage,'oneoffjob-images');
             array_push($images, $imageName);
           }

           $updateData = $this->api_model->updateOneOffJobData($update,$insert,$images,$jobData->oneofid);
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
     * Get List of Audits
     */

    public function auditList_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $filter_by = '';
            if(isset($postData['filter_by'])){
              $filter_by = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
              if($filter_by == 'week')
              {
                $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
                $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
              }
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           //print_r($userData);die;
           $searchKeyword = '';
           
           if(isset($postData['search_keyword']))
           {
             $searchKeyword = $this->security->xss_clean($postData['search_keyword']);
           }
           if(isset($postData['filter_value'])){
              $requiredData['filter_value'] = $this->security->xss_clean($postData['filter_value']);
            }
            else
            {
              $requiredData['filter_value'] = '';
            }

           if(!is_numeric($requiredData['page']))
           {
             $this->_send_response(FALSE,'Invalid page'); 
             exit();
           } 

            $page = (int) $requiredData['page'];
            if($page == 0)
            {
              $this->_send_response(FALSE,'Invalid page'); 
              exit();
            }          
           $audit_by_me = 0;

           $responseData = $this->api_model->get_auditList($userData->worker_id,$userData->company_id,$searchKeyword,$filter_by,$requiredData,$page,$audit_by_me);
           $auditData = $responseData['data'];
           if($auditData)
           {
            foreach($auditData as $audit)
            {
              if($audit->client_firstname == null)
                $audit->client_firstname = '';
              if($audit->client_lastname == null)
                $audit->client_lastname = '';
              if($audit->audit_by_firstname == null)
                $audit->audit_by_firstname = '';
              if($audit->audit_by_lastname == null)
                $audit->audit_by_lastname = '';
            }
            $responseData['data'] = $auditData;
           }
           
           $this->_send_response_with_pagination($responseData);
    }

    /*
     * Audit Details
     */

    public function auditDetails_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['audit_id'] = isset($postData['audit_id']) ? $this->security->xss_clean($postData['audit_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $audit_by_me = 0;

           $auditData = $this->api_model->get_auditDetails($userData->worker_id,$userData->company_id,$requiredData['audit_id']);
           if($auditData)
           {
             $cleaningarea = $this->api_model->get_auditCleaningAreas($userData->worker_id,$userData->company_id,$requiredData['audit_id'],$audit_by_me);
             foreach($cleaningarea as $cara)
             {
               $areaServices = array();
               if($cara->service)
               {
                 $areaServices = $this->api_model->get_auditServices(explode(",",$cara->service));
               }

               $cara->area_services = $areaServices;
               
               $images = $this->api_model->get_auditImages($cara->cleaningarea_id,$requiredData['audit_id']);
               foreach($images as $image)
               {
                 $image->image = $this->siteURL.'uploadmultiple/'.$image->image;
               }
               $cara->images = $images;
             }
             $auditData->cleanAreas = $cleaningarea;
             if(!$auditData->is_read)
             {
               $updateRead = $this->api_model->updateRead('ace_audit',array('aid'=>$requiredData['audit_id']));
             }

             
              if($auditData->client_firstname == null)
                $auditData->client_firstname = '';
              if($auditData->client_lastname == null)
                $auditData->client_lastname = '';
              if($auditData->audit_by_firstname == null)
                $auditData->audit_by_firstname = '';
              if($auditData->audit_by_lastname == null)
                $auditData->audit_by_lastname = '';

             $this->_send_response(TRUE,"Audit Data",$auditData);
           }
           else
           {
              $this->_send_response(FALSE,'Invalid Audit Id!');
           }
    }

    /*
     * Get List of Complaints
     */

    public function complaints_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $filter_by = '';
            if(isset($postData['filter_by'])){
              $filter_by = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
              if($filter_by == 'week')
              {
                $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
                $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
              }
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $searchKeyword = '';
           if(isset($postData['search_keyword']))
           {
             $searchKeyword = $this->security->xss_clean($postData['search_keyword']);
           }
           if(isset($postData['filter_value'])){
              $requiredData['filter_value'] = $this->security->xss_clean($postData['filter_value']);
            }
            else
            {
              $requiredData['filter_value'] = '';
            }

             if(!is_numeric($requiredData['page']))
             {
               $this->_send_response(FALSE,'Invalid page'); 
               exit();
             } 

              $page = (int) $requiredData['page'];
              if($page == 0)
              {
                $this->_send_response(FALSE,'Invalid page'); 
                exit();
              }

           $complaintData = $this->api_model->get_complaints($userData->worker_id,$userData->company_id,$searchKeyword,$filter_by,$requiredData,$page);
           
           $this->_send_response_with_pagination($complaintData);
    }

    /*
     * Complaint Details
     */

    public function complaintDetails_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['complaint_id'] = isset($postData['complaint_id']) ? $this->security->xss_clean($postData['complaint_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           $complaintData = $this->api_model->get_complaintDetails($userData->worker_id,$userData->company_id,$requiredData['complaint_id']);
           if(!$complaintData)
           {
             $this->_send_response(FALSE,'Invalid complaint_id'); 
              exit();
           }

           $feedbacks = $this->api_model->get_complaintfeedbacks($requiredData['complaint_id']);
           foreach($feedbacks as $feedback)
           {
             $feedback->worker_firstname = $complaintData->worker_firstname;
             $feedback->worker_lastname = $complaintData->worker_lastname;
             $images = array();
             if($feedback->image)
             {
                $complaint_images = explode(',', $feedback->image);
                foreach($complaint_images as $complaint_image)
                {
                  $image = new stdClass();
                  $image->image = $this->siteURL.'complaint-images/'.trim($complaint_image);
                  array_push($images, $image);
                }
             }
             
             $feedback->image = $images;
           }

           $complaintData->feedbacks = $feedbacks;
           
           
           if(!$complaintData->is_read)
           {
             $updateRead = $this->api_model->updateRead('customer_complaints',array('compid'=>$requiredData['complaint_id']));
           }
           $this->_send_response(TRUE,"Complaint Data",$complaintData);
    }

    /*
     * Get List of Priodical Jobs
     */

    public function priodicalJobList_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['page'] = isset($postData['page']) ? $this->security->xss_clean($postData['page']) : '';
            $filter_by = '';
            if(isset($postData['filter_by'])){
              $filter_by = isset($postData['filter_by']) ? $this->security->xss_clean($postData['filter_by']) : '';
              if($filter_by == 'week')
              {
                $requiredData['date_from'] = isset($postData['date_from']) ? $this->security->xss_clean($postData['date_from']) : '';
                $requiredData['date_to'] = isset($postData['date_to']) ? $this->security->xss_clean($postData['date_to']) : '';
              }
            }
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $client_id = '';
           $searchKeyword = '';
           if(isset($postData['search_keyword']))
           {
             $searchKeyword = $this->security->xss_clean($postData['search_keyword']);
           }
           if(isset($postData['client_id']))
           {
            $client_id = $this->security->xss_clean($postData['client_id']);
           }
           if(isset($postData['filter_value'])){
              $requiredData['filter_value'] = $this->security->xss_clean($postData['filter_value']);
            }
            else
            {
              $requiredData['filter_value'] = '';
            }

             if(!is_numeric($requiredData['page']))
             {
               $this->_send_response(FALSE,'Invalid page'); 
               exit();
             } 

              $page = (int) $requiredData['page'];
              if($page == 0)
              {
                $this->_send_response(FALSE,'Invalid page'); 
                exit();
              }

           $jobData = $this->api_model->getPriodicalJobs($userData->worker_id,$userData->company_id,$client_id,$searchKeyword,$filter_by,$requiredData,$page);
           $this->_send_response_with_pagination($jobData);
    }

    /*
     * Priodical Job Details
     */

    public function priodicalJobDetail_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['contract_unique_id'] = isset($postData['contract_unique_id']) ? $this->security->xss_clean($postData['contract_unique_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $jobData = $this->api_model->getPriodicalJobDetails($userData->worker_id,$userData->company_id,$requiredData['contract_unique_id']);
           if(!$jobData)
           {
             $this->_send_response(FALSE,'Invalid Priodical job!'); 
             exit();
           }

           $priodicalData = $this->api_model->priodicalData($userData->worker_id,$userData->company_id,$requiredData['contract_unique_id']);
           
           foreach($jobData as $job)
           {
             $job->due_date = $this->api_model->getPriodicalDueDates($userData->company_id,$requiredData['contract_unique_id'],$job->periodic_id,$job->required_frequency);
             if(!$job->is_read)
             {
               $updateRead = $this->api_model->updateRead('ace_contract_perdesp',array('qpd'=>$job->periodic_id));
             }
           }

           //print_r($jobData);die;
           
           $this->_send_priodical_response(TRUE,"Job Data",$jobData,$priodicalData);
    }

    /*
     * Home page Notification counts
     */

    public function homeCount_post(){
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
           $countData = $this->api_model->getHomeCounts($userData->worker_id,$userData->company_id);
           
           $this->_send_response(TRUE,"Count Data",$countData);
    }

    /*
     * Check Clocked In and Clocked Out Status
     */

    public function clockInStatus_post(){
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

           $qrCodeLoginData = $this->api_model->get_qrCodeLoginData($userData->worker_id,$userData->company_id);
           if($qrCodeLoginData)
           {
            if($qrCodeLoginData->login_status)
            {
              $res = array();
              $res['clocked_in_status'] = '1';
              // $res['cont_id'] = $qrCodeLoginData->cont_id;
              $this->_send_response(TRUE,"You are Clocked In",$res);
            }
            else
            {
              $res = array();
              $res['clocked_in_status'] = '0';
              $this->_send_response(TRUE,"You are Clocked Out",$res);
            }
           }
           else
           {
              $res = array();
              $res['clocked_in_status'] = '0';
              $this->_send_response(TRUE,"You are Clocked Out",$res); 
           }
           exit();
    }

    /*
     * Check GPS Status
     */

    public function gpsStatus_post(){
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

           $workerData = $this->api_model->getRowData('ace_workerstbl',array('workerid'=>$userData->worker_id),'workerid','default',array('gps_status'));
           if(!$workerData)
           {
             $this->_send_response(FALSE,'Internal server error'); 
             exit();
           }
           $res = new stdClass();
           $res->gps_status = $workerData->gps_status;
           $this->_send_response(TRUE,"GPS Status",$res);
           exit();
    }

    /*
     * Change GPS Status
     */

    public function changeGpsStatus_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['status'] = isset($postData['status']) ? $this->security->xss_clean($postData['status']) : '';
            $requiredData['latitude'] = isset($postData['latitude']) ? $this->security->xss_clean($postData['latitude']) : '';
            $requiredData['longitude'] = isset($postData['longitude']) ? $this->security->xss_clean($postData['longitude']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);

           if($requiredData['status'] == '1' || $requiredData['status'] == 1)
           {
             $status = '1';
             $wType = 'work_start';
           }
           else
           {
            $status = '0';
            $wType = 'work_stop';
           }

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['worker_id'] = $userData->worker_id;
           $insert['wtype'] = $wType;
           $insert['long'] = $requiredData['longitude'];
           $insert['lat'] = $requiredData['latitude'];
           $insert['wdate'] = date('Y-m-d');
           $insert['wtime'] = date('H:i:s');
           $insert['created_time'] = date('Y-m-d H:i:s');

           $statusUpdate = $this->api_model->updateGpsStatus($userData->worker_id,$status,$insert);
           if(!$statusUpdate)
           {
             $this->_send_response(FALSE,'Internal server error'); 
             exit();
           }
           $res = new stdClass();
           $res->gps_status = $status;
           $this->_send_response(TRUE,"GPS Status Changed",$res);
           exit();
    }

    /*
     * Change GPS Status at midnight using Cron Job
     */

    public function changeAllGpsStatus_get(){
            
           $this->api_model->changeAllGpsStatus();
           $res = new stdClass();
           $this->_send_response(TRUE,"GPS Status Changed",$res);
           exit();
    }

    /*
     * save GPS location
     */

    public function saveGpsLocation_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['latitude'] = isset($postData['latitude']) ? $this->security->xss_clean($postData['latitude']) : '';
            $requiredData['longitude'] = isset($postData['longitude']) ? $this->security->xss_clean($postData['longitude']) : '';
             /* This API hidden from here */
             $res = new stdClass();
             $res->latitude = $requiredData['latitude'];
             $res->longitude = $requiredData['longitude'];
             $this->_send_response(TRUE,"Location saved",$res); 
             exit();
             /* exit after hidden */
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

            $latitude = $requiredData['latitude'];
            $longitude = $requiredData['longitude'];

           $userData = $this->getUserData($requiredData['token']);
           $tr = 0;

           $insert = array();
           $insert['company_id'] = $userData->company_id;
           $insert['worker_id'] = $userData->worker_id;
           $insert['wtype'] = 'gps';
           $insert['long'] = $requiredData['longitude'];
           $insert['lat'] = $requiredData['latitude'];
           $insert['wdate'] = date('Y-m-d');
           $insert['wtime'] = date('H:i:s');
           $insert['created_time'] = date('Y-m-d H:i:s');

           
           $saveLogs = $this->api_model->getSavedLogData($userData);
           if(!$saveLogs)
           {
               $customers = $this->api_model->get_customerData($userData->company_id,array('latitude','longitude','customerid')); 
               foreach($customers as $customer)
               {
                 $distance = $this->getDistanceBetweenPoints($customer->latitude,$customer->longitude,$latitude,$longitude);
                        
                if($distance['meters'] < 51)
                {
                    $isertTotal = array();
                    $isertTotal['company_id'] = $userData->company_id;
                    $isertTotal['worker_id'] = $userData->worker_id;
                    $isertTotal['customer_id'] = $customer->customerid;
                    $isertTotal['start'] = date('H:i:s');
                    $isertTotal['end'] = '00:00:00';
                    $isertTotal['total'] = '00:00:00';
                    $isertTotal['date'] = date('Y-m-d');
                    $isertTotal['datetime'] = date('Y-m-d H:i:s');
                    $this->api_model->saveGpsWithClient($insert,$isertTotal);
                    $tr = 1;
                    break;
                }
               }
           }
           else{

                $customer = $this->api_model->getCustomer($saveLogs->customer_id,array('latitude','longitude','customerid'));

                 if($customer)
                 {
                     if(trim($saveLogs->end) == '00:00:00')
                     {
                            $distance = $this->getDistanceBetweenPoints($customer->latitude,$customer->longitude,$latitude,$longitude);
                            if($distance['meters'] > 50)
                            {
                                $currentDateTime = date('Y-m-d H:i:s');
                                $currentTime = date('H:i:s');
                                $totalTime = $this->api_model->timeDifference($saveLogs->datetime,$currentDateTime);
                                $updateTotal = array();
                                $updateTotal['end'] = $currentTime;
                                $updateTotal['total'] = $totalTime;
                                $updateTotal['date'] = date('Y-m-d');
                                $updateTotal['datetime'] = $currentDateTime;
                                $this->api_model->updateGpsWithClient($insert,$updateTotal,$saveLogs->id);
                                $tr = 1;
                            }
                     }
                     else
                     {
                            $distance = $this->getDistanceBetweenPoints($customer->latitude,$customer->longitude,$latitude,$longitude);
                            if($distance['meters'] < 51)
                            {
                                $isertTotal = array();
                                $isertTotal['company_id'] = $userData->company_id;
                                $isertTotal['worker_id'] = $userData->worker_id;
                                $isertTotal['customer_id'] = $customer->customerid;
                                $isertTotal['start'] = date('H:i:s');
                                $isertTotal['end'] = '00:00:00';
                                $isertTotal['total'] = '00:00:00';
                                $isertTotal['date'] = date('Y-m-d');
                                $isertTotal['datetime'] = date('Y-m-d H:i:s');
                                $this->api_model->saveGpsWithClient($insert,$isertTotal);
                                $tr = 1;
                            }
                     } 
                 }  
           } 
           
           // if(!$tr)
           // {
           //     $this->api_model->insert('ace_worker_log',$insert);
           // }
           
           $res = new stdClass();
           $res->latitude = $requiredData['latitude'];
           $res->longitude = $requiredData['longitude'];
           $this->_send_response(TRUE,"Location saved",$res); 
           exit();
    }

    /*
     * Clocked In using QR Code
     */

    public function qrCodeClockIn_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['qr_code_data'] = isset($postData['qr_code_data']) ? $this->security->xss_clean($postData['qr_code_data']) : '';
            $requiredData['lattitude'] = isset($postData['lattitude']) ? $this->security->xss_clean($postData['lattitude']) : '';
            $requiredData['longitude'] = isset($postData['longitude']) ? $this->security->xss_clean($postData['longitude']) : '';
            $requiredData['start_date'] = isset($postData['start_date']) ? $this->security->xss_clean($postData['start_date']) : '';
            $requiredData['start_time'] = isset($postData['start_time']) ? $this->security->xss_clean($postData['start_time']) : '';
            // $requiredData['cont_id'] = isset($postData['cont_id']) ? $this->security->xss_clean($postData['cont_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

            if((!$this->isGeoValid('latitude',$requiredData['lattitude'])) || (!$this->isGeoValid('longitude',$requiredData['longitude'])))
            {
              $this->_send_response(FALSE,"Invalid current location"); 
              exit();
            }

           $userData = $this->getUserData($requiredData['token']);
           $qr_data = explode($this->qrCodeSecret, $requiredData['qr_code_data']);
           if(!is_array($qr_data))
           {
             $this->_send_response(FALSE,"Invalid qr data!"); 
             exit();
           }
           if(sizeof($qr_data) != 3)
           {
             $this->_send_response(FALSE,"Invalid qr data!"); 
             exit();
           }

           $enc_customerId = base64_decode(base64_decode($qr_data[1]));
           $enc_identifierId = base64_decode(base64_decode($qr_data[2]));

           $customerData = $this->api_model->get_customerDataUsingEncryptedId($enc_customerId,array('customerid','latitude','longitude'));
           if(!$customerData)
           {
            $this->_send_response(FALSE,"Invalid customer!"); 
            exit();
           }

            // $contractData = $this->api_model->getSheduleData($requiredData['cont_id'],array('fdate','tdate','customer'));
            // if(!$contractData)
            // {
            //   $this->_send_response(FALSE,"Invalid contract id"); 
            //   exit();
            // }

            // if($contractData->customer != $customerData->customerid)
            // {
            //   $this->_send_response(FALSE,"Invalid customer"); 
            //   exit();
            // }

            // if(date('Y-m-d 00:00:01',strtotime($contractData->fdate)) > date('Y-m-d H:i:s') || date('Y-m-d 23:59:59',strtotime($contractData->tdate)) < date('Y-m-d H:i:s'))
            // {
            //   $this->_send_response(FALSE,"You can't Clock In for this job at this time"); 
            //   exit();
            // }
           
           $identifier_id = '0';
           $identifierData = $this->api_model->get_identifierDataUsingEncryptedId($enc_identifierId,array('aid'));
           if($identifierData)
           {
             $identifier_id = $identifierData->aid;
           }

           $qrCodeLoginData = $this->api_model->get_qrCodeLoginData($userData->worker_id,$userData->company_id);
           if($qrCodeLoginData)
           {
            if($qrCodeLoginData->login_status)
            {
              $this->_send_response(FALSE,"Already Clocked In!"); 
              exit();
            }

            if($customerData->latitude && $customerData->longitude)
            {
                
              if($this->isGeoValid('latitude',$customerData->latitude) && $this->isGeoValid('longitude',$customerData->longitude))
              {
                $distance = $this->getDistanceBetweenPoints($customerData->latitude,$customerData->longitude,$requiredData['lattitude'],$requiredData['longitude']);
                
                if($distance['meters'] > $this->locationDiameter)
                {
                  $this->_send_response(FALSE,"location not matched"); 
                  exit();
                }
              }
              else
              {
                $this->_send_response(FALSE,"Invalid client's location"); 
                exit();
              }
            }
            else
            {
              $this->_send_response(FALSE,"Invalid client's location"); 
              exit();
            }

            
              $insert = array();
              $insert['identifier_id'] = $identifier_id;
              $insert['company_id'] = $userData->company_id;
              $insert['worker_id'] = $userData->worker_id;
              $insert['customer'] = $customerData->customerid;
              $insert['login_status'] = '1';
              $insert['wtype'] = 'login';
              $insert['wdate'] = $requiredData['start_date'];
              $insert['wtime'] = $requiredData['start_time'];
              // $insert['cont_id'] = $requiredData['cont_id'];
              $insert['created_time'] = $requiredData['start_date'].' '.$requiredData['start_time'];
           }
           else
           {
              $insert = array();
              $insert['identifier_id'] = $identifier_id;
              $insert['company_id'] = $userData->company_id;
              $insert['worker_id'] = $userData->worker_id;
              $insert['customer'] = $customerData->customerid;
              $insert['login_status'] = '1';
              $insert['wtype'] = 'login';
              $insert['wdate'] = $requiredData['start_date'];
              $insert['wtime'] = $requiredData['start_time'];
              // $insert['cont_id'] = $requiredData['cont_id'];
              $insert['created_time'] = $requiredData['start_date'].' '.$requiredData['start_time'];
           }

           $insertLocation = array();
           $insertLocation['company_id'] = $userData->company_id;
           $insertLocation['worker_id'] = $userData->worker_id;
           $insertLocation['lattitude'] = $requiredData['lattitude'];
           $insertLocation['langitude'] = $requiredData['longitude'];
           $insertLocation['date'] = $requiredData['start_date'].' '.$requiredData['start_time'];
           $insertLocation['login_date'] = $requiredData['start_date'];
           $insertLocation['start_time'] = $requiredData['start_time'];
           $insertLocation['start'] = 1;
           $insertLocation['end'] = 0;

           $clockInSave = $this->api_model->clockIn($insert,$insertLocation);
           if(!$clockInSave)
           {
              $this->_send_response(FALSE,"Internal server error"); 
              exit();
           }
           else
           {
             $this->_send_response(TRUE,"Clocked In successfully"); 
             exit();
           }
    }

    /*
     * Clocked Out using QR Code
     */

    public function qrCodeClockOut_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['qr_code_data'] = isset($postData['qr_code_data']) ? $this->security->xss_clean($postData['qr_code_data']) : '';
            $requiredData['lattitude'] = isset($postData['lattitude']) ? $this->security->xss_clean($postData['lattitude']) : '';
            $requiredData['longitude'] = isset($postData['longitude']) ? $this->security->xss_clean($postData['longitude']) : '';
            $requiredData['end_date'] = isset($postData['end_date']) ? $this->security->xss_clean($postData['end_date']) : '';
            $requiredData['end_time'] = isset($postData['end_time']) ? $this->security->xss_clean($postData['end_time']) : '';
            // $requiredData['cont_id'] = isset($postData['cont_id']) ? $this->security->xss_clean($postData['cont_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

            if((!$this->isGeoValid('latitude',$requiredData['lattitude'])) || (!$this->isGeoValid('longitude',$requiredData['longitude'])))
            {
              $this->_send_response(FALSE,"Invalid current location"); 
              exit();
            }

           $userData = $this->getUserData($requiredData['token']);
           $qr_data = explode($this->qrCodeSecret, $requiredData['qr_code_data']);
           if(!is_array($qr_data))
           {
             $this->_send_response(FALSE,"Invalid qr data!"); 
             exit();
           }
           if(sizeof($qr_data) != 3)
           {
             $this->_send_response(FALSE,"Invalid qr data!"); 
             exit();
           }

           $enc_customerId = base64_decode(base64_decode($qr_data[1]));
           $enc_identifierId = base64_decode(base64_decode($qr_data[2]));

           $customerData = $this->api_model->get_customerDataUsingEncryptedId($enc_customerId,array('customerid','latitude','longitude'));
           if(!$customerData)
           {
            $this->_send_response(FALSE,"Invalid customer!"); 
            exit();
           }

            // $contractData = $this->api_model->getSheduleData($requiredData['cont_id'],array('fdate','tdate','customer'));
            // if(!$contractData)
            // {
            //   $this->_send_response(FALSE,"Invalid contract id"); 
            //   exit();
            // }

            // if($contractData->customer != $customerData->customerid)
            // {
            //   $this->_send_response(FALSE,"Invalid customer"); 
            //   exit();
            // }

            // if(date('Y-m-d 00:00:01',strtotime($contractData->fdate)) > date('Y-m-d H:i:s') || date('Y-m-d 23:59:59',strtotime($contractData->tdate)) < date('Y-m-d H:i:s'))
            // {
            //   $this->_send_response(FALSE,"You can't Clock Out for this job at this time"); 
            //   exit();
            // }
           
           $identifier_id = '0';
           $identifierData = $this->api_model->get_identifierDataUsingEncryptedId($enc_identifierId,array('aid'));
           if($identifierData)
           {
             $identifier_id = $identifierData->aid;
           }

           $qrCodeLoginData = $this->api_model->get_qrCodeLoginData($userData->worker_id,$userData->company_id);
           if(!$qrCodeLoginData)
           {
             $this->_send_response(FALSE,"You didn't Clocked In"); 
             exit();
           }

            if(!$qrCodeLoginData->login_status)
            {
              $this->_send_response(FALSE,"Already Clocked Out!"); 
              exit();
            }

            // if($qrCodeLoginData->cont_id != $requiredData['cont_id'])
            // {
            //   $this->_send_response(FALSE,"Invalid contract id"); 
            //   exit();
            // }

            if($customerData->latitude && $customerData->longitude)
            {
              if($this->isGeoValid('latitude',$customerData->latitude) && $this->isGeoValid('longitude',$customerData->longitude))
              {
                $distance = $this->getDistanceBetweenPoints($customerData->latitude,$customerData->longitude,$requiredData['lattitude'],$requiredData['longitude']);
                if($distance['meters'] > $this->locationDiameter)
                {
                  $this->_send_response(FALSE,"location not matched"); 
                  exit();
                }
              }
              else
              {
                $this->_send_response(FALSE,"Invalid client's location"); 
                exit();
              }
            }
            else
            {
              $this->_send_response(FALSE,"Invalid client's location"); 
              exit();
            }

           $locationData = $this->api_model->get_qrCodeLocationData($userData->worker_id,$userData->company_id,array('lid'));

            
              $insert = array();
              $insert['identifier_id'] = $identifier_id;
              $insert['company_id'] = $userData->company_id;
              $insert['worker_id'] = $userData->worker_id;
              $insert['customer'] = $customerData->customerid;
              $insert['login_status'] = '0';
              $insert['wtype'] = 'logout';
              $insert['wdate'] = $requiredData['end_date'];
              $insert['wtime'] = $requiredData['end_time'];
              // $insert['cont_id'] = $qrCodeLoginData->cont_id;
              $insert['created_time'] = $requiredData['end_date'].' '.$requiredData['end_time'];

               $updateLocation = array();
               $updateLocation['end_lattitude'] = $requiredData['lattitude'];
               $updateLocation['end_longitude'] = $requiredData['longitude'];
               $updateLocation['end_time'] = $requiredData['end_time'];
               $updateLocation['end'] = 1;

               $totalTime = $this->api_model->timeDifference($qrCodeLoginData->created_time,$insert['created_time']);

               $clockOutSave = $this->api_model->clockOut($insert,$updateLocation,$locationData,$totalTime,$qrCodeLoginData->wtime);
               if(!$clockOutSave)
               {
                  $this->_send_response(FALSE,"Internal server error"); 
                  exit();
               }
               else
               {
                 $res = new stdClass();
                  $res->date = $insert['created_time'];
                  $res->total_time = $totalTime;
                  $res->week_total_time = $this->api_model->weeksTotal($userData->worker_id,$userData->company_id);
                 $this->_send_response(TRUE,"Clocked Out successfully",$res); 
                 exit();
               }
    }

    /*
     * Get List of Notifications
     */

    public function notifications_post(){
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
           $notifications = $this->api_model->getNotifications($userData->worker_id);
           
           $this->_send_response(TRUE,"Notifications",$notifications);
    }

    /*
     * Read a Notification
     */

    public function readNotification_post(){
            $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            $requiredData['notification_id'] = isset($postData['notification_id']) ? $this->security->xss_clean($postData['notification_id']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $userData = $this->getUserData($requiredData['token']);
           $notifications = $this->api_model->updateRead('ace_notifications',array('id'=>$requiredData['notification_id']));
           $res = new stdClass();
           $res->notification_id = $requiredData['notification_id'];
           $res->token = $requiredData['token'];
           $this->_send_response(TRUE,"Notification read successfully",$res);
    }

    /*
     * Get List of Clients
     */

    public function getClients_post(){
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
           $clients = $this->api_model->getClients($userData->company_id);
           
           $this->_send_response(TRUE,"clients",$clients);
    }

    /*
     * Worker Logout
     */

    public function logout_post(){
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
           
            $deviceData = array();
            $deviceData['is_login'] = '0';
            $deviceData['updated_at'] = date('Y-m-d H:i:s');
           $logout = $this->api_model->updateRowData('ace_workers_devices',$deviceData,array('worker_id'=>$userData->worker_id));
           $res = new stdClass();
           $this->_send_response(TRUE,"Logout successfully",$res);
    }

    /*
     * Settings
     */

    public function settings_post(){
        $postData=jsonToArray(file_get_contents("php://input"));
            $requiredData['token'] = isset($postData['token']) ? $this->security->xss_clean($postData['token']) : '';
            
            foreach ($requiredData as $key => $val) {
                if (trim($val) == '') {
                    $message = 'Please Specify ' . ucwords(str_replace("_", " ", $key));
                    $this->_send_response(FALSE,$message); 
                    exit();
                }
            }

           $response = new stdClass();
           $response->google_api_key = $this->googleApiKey;
           $this->_send_response(TRUE,"Settings",$response);
    }

    /*
     * Encrypt Data
     */

    public function encryptData_post(){
        $data = $this->input->post(NULL, TRUE);
        echo json_encode($this->json_encode_cbc($data));
        exit();
    }

    /*
     * Decrypt Data
     */

    public function decryptData_post(){
        $data=jsonToArray(file_get_contents("php://input"));
        print_r($data);
        exit();  
    }

    /*
     * Test
     */

    public function test_post(){
        $service_str = "12";
        $services = $this->api_model->get_auditServices(explode(",",$service_str));
        foreach($services as $service)
        {
          echo $service->service_name.'==';
        }
    }

    /*
     * Get Expire Time for User's Token
     */

    private function expirydate($value=''){

       $startTime = date("Y-m-d H:i:s");
       $cenvertedTime = date('Y-m-d H:i:s',strtotime('+24 hours',strtotime($startTime)));    
       return $cenvertedTime;   
    }

    /*
     * Get Distance between Two Locations
     */

    private function getDistanceBetweenPoints($lat1, $lon1, $lat2, $lon2) {
        $theta = $lon1 - $lon2;
        $miles = (sin(deg2rad($lat1)) * sin(deg2rad($lat2))) + (cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * cos(deg2rad($theta)));
        $miles = acos($miles);
        $miles = rad2deg($miles);
        $miles = $miles * 60 * 1.1515;
        $feet = $miles * 5280;
        $yards = $feet / 3;
        $kilometers = $miles * 1.609344;
        $meters = $kilometers * 1000;
        return compact('miles','feet','yards','kilometers','meters'); 
      }

    /*
     * Get User's Data using Token
     */

    public function getUserData($token){
      try{
           $userData = jwt::validateToken($token);
           if(!isset($userData->device_token))
           {
             $update = $this->api_model->updateRowData('ace_workers_devices',array('is_login'=>'0','updated_at'=>date('Y-m-d H:i:s')),array('worker_id'=>$userData->worker_id));
             $this->_send_response(FALSE,'Token expired!'); 
             exit();
           }

           $device_data = $this->api_model->getRowData('ace_workers_devices',array('worker_id'=>$userData->worker_id),'id','default',array('device_token','is_login'));
           if(!$device_data)
           {
             $this->_send_response(FALSE,'Access denied!'); 
             exit();
           }
           if($device_data->device_token == $userData->device_token && $device_data->is_login)
           {
               if($userData->expire_at < date('Y-m-d H:i:s'))
               {
                 $update = $this->api_model->updateRowData('ace_workers_devices',array('is_login'=>'0','updated_at'=>date('Y-m-d H:i:s')),array('worker_id'=>$userData->worker_id));
                 $this->_send_response(FALSE,'Token expired!'); 
                 exit();
               }
               else
               {
                 return $userData;
               }
           }
           else
           {
             $this->_send_response(FALSE,'Token expired!'); 
             exit();
           }
           
        }
        catch(Exception $e) {
          $this->_send_response(FALSE,'Access denied!'); 
          exit();
        }
    }

    /*
     * Check Latitude/Longitude is Valid or not
     */

    private function isGeoValid($type, $value){
        $value = number_format($value,6);
        $pattern = ($type == 'latitude')
            ? '/^(\+|-)?(?:90(?:(?:\.0{1,8})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,8})?))$/'
            : '/^(\+|-)?(?:180(?:(?:\.0{1,8})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,8})?))$/';
        
        if (preg_match($pattern, $value)) {
            return true;
        } else {
            return false;
        }
    }
}
