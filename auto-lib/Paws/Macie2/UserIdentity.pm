# Generated by default/object.tt
package Paws::Macie2::UserIdentity;
  use Moose;
  has AssumedRole => (is => 'ro', isa => 'Paws::Macie2::AssumedRole', request_name => 'assumedRole', traits => ['NameInRequest']);
  has AwsAccount => (is => 'ro', isa => 'Paws::Macie2::AwsAccount', request_name => 'awsAccount', traits => ['NameInRequest']);
  has AwsService => (is => 'ro', isa => 'Paws::Macie2::AwsService', request_name => 'awsService', traits => ['NameInRequest']);
  has FederatedUser => (is => 'ro', isa => 'Paws::Macie2::FederatedUser', request_name => 'federatedUser', traits => ['NameInRequest']);
  has IamUser => (is => 'ro', isa => 'Paws::Macie2::IamUser', request_name => 'iamUser', traits => ['NameInRequest']);
  has Root => (is => 'ro', isa => 'Paws::Macie2::UserIdentityRoot', request_name => 'root', traits => ['NameInRequest']);
  has Type => (is => 'ro', isa => 'Str', request_name => 'type', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Macie2::UserIdentity

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Macie2::UserIdentity object:

  $service_obj->Method(Att1 => { AssumedRole => $value, ..., Type => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Macie2::UserIdentity object:

  $result = $service_obj->Method(...);
  $result->Att1->AssumedRole

=head1 DESCRIPTION

Provides information about the type and other characteristics of an
entity that performed an action on an affected resource.

=head1 ATTRIBUTES


=head2 AssumedRole => L<Paws::Macie2::AssumedRole>

If the action was performed with temporary security credentials that
were obtained using the AssumeRole operation of the Security Token
Service (STS) API, the identifiers, session context, and other details
about the identity.


=head2 AwsAccount => L<Paws::Macie2::AwsAccount>

If the action was performed using the credentials for another Amazon
Web Services account, the details of that account.


=head2 AwsService => L<Paws::Macie2::AwsService>

If the action was performed by an Amazon Web Services account that
belongs to an Amazon Web Service, the name of the service.


=head2 FederatedUser => L<Paws::Macie2::FederatedUser>

If the action was performed with temporary security credentials that
were obtained using the GetFederationToken operation of the Security
Token Service (STS) API, the identifiers, session context, and other
details about the identity.


=head2 IamUser => L<Paws::Macie2::IamUser>

If the action was performed using the credentials for an Identity and
Access Management (IAM) user, the name and other details about the
user.


=head2 Root => L<Paws::Macie2::UserIdentityRoot>

If the action was performed using the credentials for your Amazon Web
Services account, the details of your account.


=head2 Type => Str

The type of entity that performed the action.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Macie2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

