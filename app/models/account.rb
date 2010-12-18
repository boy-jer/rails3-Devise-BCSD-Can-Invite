class Account < ActiveRecord::Base
  has_many :users
  validates_uniqueness_of :name, :case_sensitive => false
  validates_presence_of :name
  
  CAN_SIGN_UP = Rails.application.config.allow_account_sign_up
  
end
