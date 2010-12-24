class ApplicationController < ActionController::Base
  include UrlHelper
  protect_from_forgery
  helper_method :current_account, :check_account_id, :root_domain, :can_sign_up?
  before_filter :current_account
  before_filter :set_mailer_url_options

  def can_sign_up?
    root_domain ? true :Account::CAN_SIGN_UP
  end
  
  def root_domain
    result = (request.subdomains.first.present? && request.subdomains.first != "www") ? false : true
  end

  def current_account
      if !root_domain
        current_account = Account.find_by_name(request.subdomains.first)
        if current_account.nil?
          redirect_to root_url(:account => false, :alert => "Unknown Account/subdomain")
        end
      else 
        current_account = nil
        flash[:alert] = params[:alert] ||= nil  #take care of bad account from above redirect
      end
      return current_account
  end      
  
  def check_account_id(account_id)
    #call this from any controller to check if resourse account_id matches the subdomain account id
    if account_id != current_account.id
      redirect_to "/opps" , :alert => "Sorry, resource is not part of your account"
    end
  end
  
  def require_user
    # this is nothing more than authenticate_user! without a sign-in message
    unless user_signed_in?
      redirect_to root_url, :alert => "You must be logged in to access that page - #{params[:controller]}"
      return false
    end
  end
  
  def authenticate_user!
    if Rails.application.config.authenticate_to_home
      unless user_signed_in?
        redirect_to root_url, :alert => "You must be logged in to access that page - #{params[:controller]}"
        return false
      end
    else
      super
    end
  end
  
  rescue_from CanCan::AccessDenied do |exception|
    flash[:alert] = exception.message
    redirect_to "/opps" 
  end
  
  protected

  def authenticate_inviter!
    # use cancan to see if user can invite
    if can? :invite, User
      super
    else 
      redirect_to "/opps",  :alert => "Unauthorized action"
    end
  end

  def after_sign_in_path_for(resource_or_scope)
    scope = Devise::Mapping.find_scope!(resource_or_scope)
    account_name = current_user.account.name
    if current_account.nil? 
      # logout of root domain and login by token to account
      token =  Devise.friendly_token
      current_user.loginable_token = token
      current_user.save
      sign_out(current_user)
      flash[:notice] = nil
      home_path = valid_user_url(token, :account => account_name)
      return home_path 
    else
      if account_name != current_account.name 
        # user not part of current_account
        sign_out(current_user)
        flash[:notice] = nil
        flash[:alert] = "Sorry, invalid user or password for account"
      end
    end
    super
  end
  
  def sign_in_and_redirect(resource_or_scope, resource=nil)
    scope = Devise::Mapping.find_scope!(resource_or_scope)
    resource ||= resource_or_scope
    sign_in(scope, resource) unless warden.user(scope) == resource
    if check_account_id
      redirect_to stored_location_for(scope) || after_sign_in_path_for(resource)
    else
      sign_out(current_user)
      flash[:notice] = nil
      flash[:alert] = I18n.t("devise.failure.invalid") 
      redirect_to sign_in_path
    end
  end  

  def check_account_id
    current_user.account.id == current_account.id
  end
  
  
  
end
