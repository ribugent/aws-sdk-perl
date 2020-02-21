package Paws::GameLift::CertificateConfiguration;
  use Moose;
  has CertificateType => (is => 'ro', isa => 'Str', required => 1);
1;

### main pod documentation begin ###

=head1 NAME

Paws::GameLift::CertificateConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::GameLift::CertificateConfiguration object:

  $service_obj->Method(Att1 => { CertificateType => $value, ..., CertificateType => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::GameLift::CertificateConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->CertificateType

=head1 DESCRIPTION

Information about the use of a TLS/SSL certificate for a fleet. TLS
certificate generation is enabled at the fleet level, with one
certificate generated for the fleet. When this feature is enabled, the
certificate can be retrieved using the GameLift Server SDK
(https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk.html)
call C<GetInstanceCertificate>. All instances in a fleet share the same
certificate.

=head1 ATTRIBUTES


=head2 B<REQUIRED> CertificateType => Str

  Indicates whether a TLS/SSL certificate was generated for a fleet.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::GameLift>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

