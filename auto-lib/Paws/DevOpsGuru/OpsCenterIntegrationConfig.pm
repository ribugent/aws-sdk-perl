# Generated by default/object.tt
package Paws::DevOpsGuru::OpsCenterIntegrationConfig;
  use Moose;
  has OptInStatus => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DevOpsGuru::OpsCenterIntegrationConfig

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DevOpsGuru::OpsCenterIntegrationConfig object:

  $service_obj->Method(Att1 => { OptInStatus => $value, ..., OptInStatus => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DevOpsGuru::OpsCenterIntegrationConfig object:

  $result = $service_obj->Method(...);
  $result->Att1->OptInStatus

=head1 DESCRIPTION

Information about whether DevOps Guru is configured to create an
OpsItem in AWS Systems Manager OpsCenter for each created insight.

=head1 ATTRIBUTES


=head2 OptInStatus => Str

Specifies if DevOps Guru is enabled to create an AWS Systems Manager
OpsItem for each created insight.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DevOpsGuru>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

