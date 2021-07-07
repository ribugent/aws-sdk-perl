# Generated by default/object.tt
package Paws::CognitoIdp::UserPoolType;
  use Moose;
  has AccountRecoverySetting => (is => 'ro', isa => 'Paws::CognitoIdp::AccountRecoverySettingType');
  has AdminCreateUserConfig => (is => 'ro', isa => 'Paws::CognitoIdp::AdminCreateUserConfigType');
  has AliasAttributes => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has Arn => (is => 'ro', isa => 'Str');
  has AutoVerifiedAttributes => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has CreationDate => (is => 'ro', isa => 'Str');
  has CustomDomain => (is => 'ro', isa => 'Str');
  has DeviceConfiguration => (is => 'ro', isa => 'Paws::CognitoIdp::DeviceConfigurationType');
  has Domain => (is => 'ro', isa => 'Str');
  has EmailConfiguration => (is => 'ro', isa => 'Paws::CognitoIdp::EmailConfigurationType');
  has EmailConfigurationFailure => (is => 'ro', isa => 'Str');
  has EmailVerificationMessage => (is => 'ro', isa => 'Str');
  has EmailVerificationSubject => (is => 'ro', isa => 'Str');
  has EstimatedNumberOfUsers => (is => 'ro', isa => 'Int');
  has Id => (is => 'ro', isa => 'Str');
  has LambdaConfig => (is => 'ro', isa => 'Paws::CognitoIdp::LambdaConfigType');
  has LastModifiedDate => (is => 'ro', isa => 'Str');
  has MfaConfiguration => (is => 'ro', isa => 'Str');
  has Name => (is => 'ro', isa => 'Str');
  has Policies => (is => 'ro', isa => 'Paws::CognitoIdp::UserPoolPolicyType');
  has SchemaAttributes => (is => 'ro', isa => 'ArrayRef[Paws::CognitoIdp::SchemaAttributeType]');
  has SmsAuthenticationMessage => (is => 'ro', isa => 'Str');
  has SmsConfiguration => (is => 'ro', isa => 'Paws::CognitoIdp::SmsConfigurationType');
  has SmsConfigurationFailure => (is => 'ro', isa => 'Str');
  has SmsVerificationMessage => (is => 'ro', isa => 'Str');
  has Status => (is => 'ro', isa => 'Str');
  has UsernameAttributes => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has UsernameConfiguration => (is => 'ro', isa => 'Paws::CognitoIdp::UsernameConfigurationType');
  has UserPoolAddOns => (is => 'ro', isa => 'Paws::CognitoIdp::UserPoolAddOnsType');
  has UserPoolTags => (is => 'ro', isa => 'Paws::CognitoIdp::UserPoolTagsType');
  has VerificationMessageTemplate => (is => 'ro', isa => 'Paws::CognitoIdp::VerificationMessageTemplateType');

1;

### main pod documentation begin ###

=head1 NAME

Paws::CognitoIdp::UserPoolType

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CognitoIdp::UserPoolType object:

  $service_obj->Method(Att1 => { AccountRecoverySetting => $value, ..., VerificationMessageTemplate => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CognitoIdp::UserPoolType object:

  $result = $service_obj->Method(...);
  $result->Att1->AccountRecoverySetting

=head1 DESCRIPTION

A container for information about the user pool.

=head1 ATTRIBUTES


=head2 AccountRecoverySetting => L<Paws::CognitoIdp::AccountRecoverySettingType>

Use this setting to define which verified available method a user can
use to recover their password when they call C<ForgotPassword>. It
allows you to define a preferred method when a user has more than one
method available. With this setting, SMS does not qualify for a valid
password recovery mechanism if the user also has SMS MFA enabled. In
the absence of this setting, Cognito uses the legacy behavior to
determine the recovery method where SMS is preferred over email.


=head2 AdminCreateUserConfig => L<Paws::CognitoIdp::AdminCreateUserConfigType>

The configuration for C<AdminCreateUser> requests.


=head2 AliasAttributes => ArrayRef[Str|Undef]

Specifies the attributes that are aliased in a user pool.


=head2 Arn => Str

The Amazon Resource Name (ARN) for the user pool.


=head2 AutoVerifiedAttributes => ArrayRef[Str|Undef]

Specifies the attributes that are auto-verified in a user pool.


=head2 CreationDate => Str

The date the user pool was created.


=head2 CustomDomain => Str

A custom domain name that you provide to Amazon Cognito. This parameter
applies only if you use a custom domain to host the sign-up and sign-in
pages for your application. For example: C<auth.example.com>.

For more information about adding a custom domain to your user pool,
see Using Your Own Domain for the Hosted UI
(https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html).


=head2 DeviceConfiguration => L<Paws::CognitoIdp::DeviceConfigurationType>

The device configuration.


=head2 Domain => Str

Holds the domain prefix if the user pool has a domain associated with
it.


=head2 EmailConfiguration => L<Paws::CognitoIdp::EmailConfigurationType>

The email configuration.


=head2 EmailConfigurationFailure => Str

The reason why the email configuration cannot send the messages to your
users.


=head2 EmailVerificationMessage => Str

The contents of the email verification message.


=head2 EmailVerificationSubject => Str

The subject of the email verification message.


=head2 EstimatedNumberOfUsers => Int

A number estimating the size of the user pool.


=head2 Id => Str

The ID of the user pool.


=head2 LambdaConfig => L<Paws::CognitoIdp::LambdaConfigType>

The AWS Lambda triggers associated with the user pool.


=head2 LastModifiedDate => Str

The date the user pool was last modified.


=head2 MfaConfiguration => Str

Can be one of the following values:

=over

=item *

C<OFF> - MFA tokens are not required and cannot be specified during
user registration.

=item *

C<ON> - MFA tokens are required for all user registrations. You can
only specify required when you are initially creating a user pool.

=item *

C<OPTIONAL> - Users have the option when registering to create an MFA
token.

=back



=head2 Name => Str

The name of the user pool.


=head2 Policies => L<Paws::CognitoIdp::UserPoolPolicyType>

The policies associated with the user pool.


=head2 SchemaAttributes => ArrayRef[L<Paws::CognitoIdp::SchemaAttributeType>]

A container with the schema attributes of a user pool.


=head2 SmsAuthenticationMessage => Str

The contents of the SMS authentication message.


=head2 SmsConfiguration => L<Paws::CognitoIdp::SmsConfigurationType>

The SMS configuration.


=head2 SmsConfigurationFailure => Str

The reason why the SMS configuration cannot send the messages to your
users.

This message might include comma-separated values to describe why your
SMS configuration can't send messages to user pool end users.

=over

=item *

InvalidSmsRoleAccessPolicyException - The IAM role which Cognito uses
to send SMS messages is not properly configured. For more information,
see SmsConfigurationType
(https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SmsConfigurationType.html).

=item *

SNSSandbox - The AWS account is in SNS Sandbox and messages
wonE<rsquo>t reach unverified end users. This parameter wonE<rsquo>t
get populated with SNSSandbox if the IAM user creating the user pool
doesnE<rsquo>t have SNS permissions. To learn how to move your AWS
account out of the sandbox, see Moving out of the SMS sandbox
(https://docs.aws.amazon.com/sns/latest/dg/sns-sms-sandbox-moving-to-production.html).

=back



=head2 SmsVerificationMessage => Str

The contents of the SMS verification message.


=head2 Status => Str

The status of a user pool.


=head2 UsernameAttributes => ArrayRef[Str|Undef]

Specifies whether email addresses or phone numbers can be specified as
usernames when a user signs up.


=head2 UsernameConfiguration => L<Paws::CognitoIdp::UsernameConfigurationType>

You can choose to enable case sensitivity on the username input for the
selected sign-in option. For example, when this is set to C<False>,
users will be able to sign in using either "username" or "Username".
This configuration is immutable once it has been set. For more
information, see UsernameConfigurationType
(https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UsernameConfigurationType.html).


=head2 UserPoolAddOns => L<Paws::CognitoIdp::UserPoolAddOnsType>

The user pool add-ons.


=head2 UserPoolTags => L<Paws::CognitoIdp::UserPoolTagsType>

The tags that are assigned to the user pool. A tag is a label that you
can apply to user pools to categorize and manage them in different
ways, such as by purpose, owner, environment, or other criteria.


=head2 VerificationMessageTemplate => L<Paws::CognitoIdp::VerificationMessageTemplateType>

The template for verification messages.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CognitoIdp>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

