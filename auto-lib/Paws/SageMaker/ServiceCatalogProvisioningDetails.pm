# Generated by default/object.tt
package Paws::SageMaker::ServiceCatalogProvisioningDetails;
  use Moose;
  has PathId => (is => 'ro', isa => 'Str');
  has ProductId => (is => 'ro', isa => 'Str', required => 1);
  has ProvisioningArtifactId => (is => 'ro', isa => 'Str', required => 1);
  has ProvisioningParameters => (is => 'ro', isa => 'ArrayRef[Paws::SageMaker::ProvisioningParameter]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::ServiceCatalogProvisioningDetails

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::ServiceCatalogProvisioningDetails object:

  $service_obj->Method(Att1 => { PathId => $value, ..., ProvisioningParameters => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::ServiceCatalogProvisioningDetails object:

  $result = $service_obj->Method(...);
  $result->Att1->PathId

=head1 DESCRIPTION

Details that you specify to provision a service catalog product. For
information about service catalog, see .What is Amazon Web Services
Service Catalog
(https://docs.aws.amazon.com/servicecatalog/latest/adminguide/introduction.html).

=head1 ATTRIBUTES


=head2 PathId => Str

The path identifier of the product. This value is optional if the
product has a default path, and required if the product has more than
one path.


=head2 B<REQUIRED> ProductId => Str

The ID of the product to provision.


=head2 B<REQUIRED> ProvisioningArtifactId => Str

The ID of the provisioning artifact.


=head2 ProvisioningParameters => ArrayRef[L<Paws::SageMaker::ProvisioningParameter>]

A list of key value pairs that you specify when you provision a
product.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

