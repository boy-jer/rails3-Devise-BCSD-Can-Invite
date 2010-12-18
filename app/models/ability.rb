#ability.rb
class Ability
  include CanCan::Ability
  def initialize(user)
    user ||= User.new  
    
    if !user.roles.nil?
      if user.roles.include?("site_admin")
        can :manage, :all
      elsif
        user.roles.include?("inviter")
        can :invite, User
      end
    end
  end
end
